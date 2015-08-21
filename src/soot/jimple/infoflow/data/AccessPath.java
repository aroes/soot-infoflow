/*******************************************************************************
 * Copyright (c) 2012 Secure Software Engineering Group at EC SPRIDE.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * 
 * Contributors: Christian Fritz, Steven Arzt, Siegfried Rasthofer, Eric
 * Bodden, and others.
 ******************************************************************************/
package soot.jimple.infoflow.data;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

import soot.ArrayType;
import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootField;
import soot.Type;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.FieldRef;
import soot.jimple.InstanceFieldRef;
import soot.jimple.StaticFieldRef;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.infoflow.collect.MyConcurrentHashMap;
import soot.jimple.infoflow.util.TypeUtils;

/**
 * This class represents the taint, containing a base value and a list of fields
 * (length is bounded by Infoflow.ACCESSPATHLENGTH)
 */
public class AccessPath implements Cloneable {
	
	public enum ArrayTaintType {
		Contents,
		Length,
		ContentsAndLength
	}
	
	// ATTENTION: This class *must* be immutable!
	/*
	 * tainted value, is not null for non-static values
	 */
	private final Local value;
	/**
	 * list of fields, either they are based on a concrete @value or they indicate a static field
	 */
	private final SootField[] fields;
	
	private final Type baseType;
	private final Type[] fieldTypes;
	
	private final boolean taintSubFields;
	private final boolean cutOffApproximation;
	private final ArrayTaintType arrayTaintType;
	
	private int hashCode = 0;
	
	/**
	 * Specialized pair class for field bases
	 * 
	 * @author Steven Arzt
	 *
	 */
	public static class BasePair {
		
		private final SootField[] fields;
		private final Type[] types;
		private int hashCode = 0;
		
		private BasePair(SootField[] fields, Type[] types) {
			this.fields = fields;
			this.types = types;
			
			// Check whether this base makes sense
			if (fields == null || fields.length == 0)
				throw new RuntimeException("A base must contain at least one field");
		}
		
		public SootField[] getFields() {
			return this.fields;
		}
		
		public Type[] getTypes()  {
			return this.types;
		}
		
		@Override
		public int hashCode() {
			if (hashCode == 0) {			
				final int prime = 31;
				int result = 1;
				result = prime * result + Arrays.hashCode(fields);
				result = prime * result + Arrays.hashCode(types);
				hashCode = result;
			}
			return hashCode;
		}
		
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			BasePair other = (BasePair) obj;
			if (!Arrays.equals(fields, other.fields))
				return false;
			if (!Arrays.equals(types, other.types))
				return false;
			return true;
		}
		
		@Override
		public String toString() {
			return Arrays.toString(fields);
		}
		
	}
	
	private static MyConcurrentHashMap<Type, Set<BasePair>> baseRegister
			= new MyConcurrentHashMap<Type, Set<BasePair>>();

	/**
	 * The empty access path denotes a code region depending on a tainted
	 * conditional. If a function is called inside the region, there is no
	 * tainted value inside the callee, but there is taint - modeled by
	 * the empty access path.
	 */
	private static final AccessPath emptyAccessPath = new AccessPath();
	
	private AccessPath() {
		this.value = null;
		this.fields = null;
		this.baseType = null;
		this.fieldTypes = null;
		this.taintSubFields = true;
		this.cutOffApproximation = false;
		this.arrayTaintType = ArrayTaintType.ContentsAndLength;
	}
	
	public AccessPath(Value val, boolean taintSubFields){
		this(val, (SootField[]) null, null, (Type[]) null, taintSubFields,
				ArrayTaintType.ContentsAndLength);
	}
	
	public AccessPath(Value val, SootField[] appendingFields, boolean taintSubFields) {
		this(val, appendingFields, null, (Type[]) null, taintSubFields, ArrayTaintType.ContentsAndLength);
	}
	
	public AccessPath(Value val, SootField[] appendingFields, boolean taintSubFields,
			ArrayTaintType arrayTaintType) {
		this(val, appendingFields, null, (Type[]) null, taintSubFields, arrayTaintType);
	}
	
	public AccessPath(Value val, SootField[] appendingFields, Type valType,
			Type[] appendingFieldTypes, boolean taintSubFields,
			ArrayTaintType arrayTaintType) {
		this(val, appendingFields, valType, appendingFieldTypes, taintSubFields, false, true,
				arrayTaintType);
	}
	
	public AccessPath(Value val, SootField[] appendingFields, Type valType,
			Type[] appendingFieldTypes, boolean taintSubFields,
			boolean cutFirstField, boolean reduceBases,
			ArrayTaintType arrayTaintType) {
		// Make sure that the base object is valid
		assert (val == null && appendingFields != null && appendingFields.length > 0)
		 	|| canContainValue(val);
		
		// Initialize the field type information if necessary
		if (appendingFields != null && appendingFieldTypes == null) {
			appendingFieldTypes = new Type[appendingFields.length];
			for (int i = 0; i < appendingFields.length; i++)
				appendingFieldTypes[i] = appendingFields[i].getType();
		}
		
		SootField[] fields;
		Type[] fieldTypes;
		this.arrayTaintType = arrayTaintType;
		
		// Get the base object, field and type
		if(val instanceof FieldRef) {
			FieldRef ref = (FieldRef) val;

			// Set the base value and type if we have one
			if (val instanceof InstanceFieldRef) {
				InstanceFieldRef iref = (InstanceFieldRef) val;
				this.value = (Local) iref.getBase();
				this.baseType = value.getType();
			}
			else {
				this.value = null;
				this.baseType = null;
			}
			
			// Handle the fields
			fields = new SootField[(appendingFields == null ? 0 : appendingFields.length) + 1];
			fields[0] = ref.getField();
			if (appendingFields != null)
				System.arraycopy(appendingFields, 0, fields, 1, appendingFields.length);
			
			fieldTypes = new Type[(appendingFieldTypes == null ? 0 : appendingFieldTypes.length) + 1];
			fieldTypes[0] = valType != null ? valType : fields[0].getType();
			if (appendingFieldTypes != null)
				System.arraycopy(appendingFieldTypes, 0, fieldTypes, 1, appendingFieldTypes.length);
		}
		else if (val instanceof ArrayRef) {
			ArrayRef ref = (ArrayRef) val;
			this.value = (Local) ref.getBase();
			this.baseType = valType == null ? value.getType() : valType;
			
			fields = appendingFields;
			fieldTypes = appendingFieldTypes;
		}
		else {
			this.value = (Local) val;
			this.baseType = valType == null ? (this.value == null ? null : value.getType()) : valType;
			
			fields = appendingFields;
			fieldTypes = appendingFieldTypes;
		}
		
		// If we don't want to track fields at all, we can cut the field
		// processing short
		if (InfoflowConfiguration.getAccessPathLength() == 0) {
			fields = null;
			fieldTypes = null;
		}
		
		// Cut the first field if requested
		if (cutFirstField && fields != null && fields.length > 0) {
			SootField[] newFields = new SootField[fields.length - 1];
			Type[] newTypes = new Type[newFields.length];
			System.arraycopy(fields, 1, newFields, 0, newFields.length);
			System.arraycopy(fieldTypes, 1, newTypes, 0, newTypes.length);
			fields = newFields.length > 0 ? newFields : null;
			fieldTypes = newTypes.length > 0 ? newTypes : null;
		}
		
		// Make sure that only heap objects may have fields
		assert this.value == null
				|| this.value.getType() instanceof RefType 
				|| (this.value.getType() instanceof ArrayType && (((ArrayType) this.value.getType()).getArrayElementType() instanceof ArrayType
						|| ((ArrayType) this.value.getType()).getArrayElementType() instanceof RefType))
				|| fields == null || fields.length == 0;
		
		// Make sure that the actual types are always as precise as the declared ones
		if (fields != null)
			for (int i = 0; i < fields.length; i++)
				if (fields[i].getType() != fieldTypes[i]
						&& Scene.v().getFastHierarchy().canStoreType(fields[i].getType(), fieldTypes[i]))
					fieldTypes[i] = fields[i].getType();
		
		// We can always merge a.inner.this$0.c to a.c. We do this first so that
		// we don't create recursive bases for stuff we don't need anyway.
		if (InfoflowConfiguration.getUseThisChainReduction() && reduceBases && fields != null) {
			for (int i = 0; i < fields.length; i++) {
				// Is this a reference to an outer class?
				if (fields[i].getName().startsWith("this$")) {
					// Get the name of the outer class
					String outerClassName = ((RefType) fields[i].getType()).getClassName();
					
					// Check the base object
					int startIdx = -1;
					if (this.value != null
							&& this.value.getType() instanceof RefType
							&& ((RefType) this.value.getType()).getClassName().equals(outerClassName)) {
						startIdx = 0;
					}
					else {
						// Scan forward to find the same reference
						for (int j = 0; j < i; j++)
							if (fields[j].getType() instanceof RefType
									&& ((RefType) fields[j].getType()).getClassName().equals(outerClassName)) {
								startIdx = j;
								break;
							}
					}
					
					if (startIdx >= 0) {
						SootField[] newFields = new SootField[fields.length - (i - startIdx) - 1];
						Type[] newFieldTypes = new Type[fieldTypes.length - (i - startIdx) - 1];
						
						System.arraycopy(fields, 0, newFields, 0, startIdx);
						System.arraycopy(fieldTypes, 0, newFieldTypes, 0, startIdx);
						
						System.arraycopy(fields, i + 1, newFields, startIdx, fields.length - i - 1);
						System.arraycopy(fieldTypes, i + 1, newFieldTypes, startIdx, fieldTypes.length - i - 1);
						
						fields = newFields;
						fieldTypes = newFieldTypes;
						break;
					}
				}
			}
		}
		
		// Check for recursive data structures. If a last field maps back to something we
		// already know, we build a repeatable component from it
		boolean recursiveCutOff = false;
		if (InfoflowConfiguration.getUseRecursiveAccessPaths() && reduceBases && fields != null) {
			// f0...fi references an object of type T
			// look for an extension f0...fi...fj that also references an object
			// of type T
			int ei = val instanceof StaticFieldRef ? 1 : 0;
			while (ei < fields.length) {
				final Type eiType = ei == 0 ? this.baseType : fieldTypes[ei - 1];
				int ej = ei;
				while (ej < fields.length) {
					if (fieldTypes[ej] == eiType || fields[ej].getType() == eiType) {
						// The types match, f0...fi...fj maps back to an object of the
						// same type as f0...fi. We must thus convert the access path
						// to f0...fi-1[...fj]fj+1
						SootField[] newFields = new SootField[fields.length - (ej - ei) - 1];
						Type[] newTypes = new Type[newFields.length];
						
						System.arraycopy(fields, 0, newFields, 0, ei);
						System.arraycopy(fieldTypes, 0, newTypes, 0, ei);
						
						if (fields.length > ej) {
							System.arraycopy(fields, ej + 1, newFields, ei, fields.length - ej - 1);
							System.arraycopy(fieldTypes, ej + 1, newTypes, ei, fieldTypes.length - ej - 1);
						}
						
						// Register the base
						SootField[] base = new SootField[ej - ei + 1];
						Type[] baseTypes = new Type[ej - ei + 1];
						System.arraycopy(fields, ei, base, 0, base.length);
						System.arraycopy(fieldTypes, ei, baseTypes, 0, base.length);
						registerBase(eiType, base, baseTypes);
						
						fields = newFields;
						fieldTypes = newTypes;
						recursiveCutOff = true;
					}
					else
						ej++;
				}
				ei++;
			}
		}
		
		// Cut the fields at the maximum access path length. If this happens,
		// we must always add a star
		if (fields != null) {
			int fieldNum = Math.min(InfoflowConfiguration.getAccessPathLength(), fields.length);
			if (fields.length > fieldNum) {
				this.taintSubFields = true;
				this.cutOffApproximation = true;
			}
			else {
				this.taintSubFields = taintSubFields;
				this.cutOffApproximation = false || recursiveCutOff;
			}
			
			if (fieldNum == 0) {
				this.fields = null;
				this.fieldTypes = null;
			}
			else {
				this.fields = new SootField[fieldNum];
				this.fieldTypes = new Type[fieldNum];
				System.arraycopy(fields, 0, this.fields, 0, fieldNum);
				System.arraycopy(fieldTypes, 0, this.fieldTypes, 0, fieldNum);
			}
		}
		else {
			this.taintSubFields = taintSubFields;
			this.cutOffApproximation = false;
			this.fields = null;
			this.fieldTypes = null;
		}
		
		// Type checks
		assert this.value == null || !(!(this.baseType instanceof ArrayType)
				&& !TypeUtils.isObjectLikeType(this.baseType)
				&& this.value.getType() instanceof ArrayType);
		assert this.value == null || !(this.baseType instanceof ArrayType
				&& !(this.value.getType() instanceof ArrayType)
				&& !TypeUtils.isObjectLikeType(this.value.getType()))
					: "Type mismatch. Type was " + this.baseType + ", value was: " + (this.value == null ? null : this.value.getType());
		assert !isEmpty() || this.baseType == null;
		
		if (this.toString().startsWith("b(soot.jimple.infoflow.test.HeapTestCode$B) <soot.jimple.infoflow.test.HeapTestCode$B: soot.jimple.infoflow.test.HeapTestCode$A attr> <soot.jimple.infoflow.test.HeapTestCode$A: int i>"))
			System.out.println("x");
	}
	
	public AccessPath(SootField staticfield, boolean taintSubFields){
		this(null, new SootField[] { staticfield }, null,
				new Type[] { staticfield.getType() }, taintSubFields, ArrayTaintType.ContentsAndLength);
	}

	public AccessPath(Value base, SootField field, boolean taintSubFields){
		this(base, field == null ? null : new SootField[] { field }, null,
				field == null ? null : new Type[] { field.getType() },
						taintSubFields, ArrayTaintType.ContentsAndLength);
		assert base instanceof Local;
	}
	
	private static void registerBase(Type eiType, SootField[] base,
			Type[] baseTypes) {
		// Check whether we can further normalize the base
		assert base.length == baseTypes.length;
		for (int i = 0; i < base.length; i++)
			if (baseTypes[i] == eiType) {
				SootField[] newBase = new SootField[i + 1];
				Type[] newTypes = new Type[i + 1];
				
				System.arraycopy(base, 0, newBase, 0, i + 1);
				System.arraycopy(baseTypes, 0, newTypes, 0, i + 1);
				
				base = newBase;
				baseTypes = newTypes;
				break;
			}
		
		Set<BasePair> bases = baseRegister.putIfAbsentElseGet
				(eiType, new ConcurrentHashSet<BasePair>());
		bases.add(new BasePair(base, baseTypes));
	}
	
	public static void clearBaseRegister() {
		baseRegister.clear();
	}
	
	public static Collection<BasePair> getBaseForType(Type tp) {
		return baseRegister.get(tp);
	}

	/**
	 * Checks whether the given value can be the base value value of an access
	 * path
	 * @param val The value to check
	 * @return True if the given value can be the base value value of an access
	 * path
	 */
	public static boolean canContainValue(Value val) {
		return val instanceof Local
				|| val instanceof InstanceFieldRef
				|| val instanceof StaticFieldRef
				|| val instanceof ArrayRef;
	}
	
	public Local getPlainValue() {
		return value;
	}
	
	public SootField getLastField() {
		if (fields == null || fields.length == 0)
			return null;
		return fields[fields.length - 1];
	}
	
	public Type getLastFieldType() {
		if (fieldTypes == null || fieldTypes.length == 0)
			return baseType;
		return fieldTypes[fieldTypes.length - 1];
	}
	
	public SootField getFirstField(){
		if (fields == null || fields.length == 0)
			return null;
		return fields[0];
	}

	public boolean firstFieldMatches(SootField field) {
		if (fields == null || fields.length == 0)
			return false;
		if (field == fields[0])
			return true;
		return false;
	}
	
	public Type getFirstFieldType(){
		if (fieldTypes == null || fieldTypes.length == 0)
			return null;
		return fieldTypes[0];
	}

	public SootField[] getFields(){
		return fields;
	}
	
	public Type[] getFieldTypes(){
		return fieldTypes;
	}
	
	public int getFieldCount() {
		return fields == null ? 0 : fields.length;
	}
	
	@Override
	public int hashCode() {
		if (hashCode != 0)
			return hashCode;
		
		final int prime = 31;
		int result = 1;
		result = prime * result + ((fields == null) ? 0 : Arrays.hashCode(fields));
		result = prime * result + ((fieldTypes == null) ? 0 : Arrays.hashCode(fieldTypes));
		result = prime * result + ((value == null) ? 0 : value.hashCode());
		result = prime * result + ((baseType == null) ? 0 : baseType.hashCode());
		result = prime * result + (this.taintSubFields ? 1 : 0);
		result = prime * result + this.arrayTaintType.hashCode();
		this.hashCode = result;
		
		return this.hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this || super.equals(obj))
			return true;
		if (obj == null || getClass() != obj.getClass())
			return false;
		
		AccessPath other = (AccessPath) obj;
		
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		if (baseType == null) {
			if (other.baseType != null)
				return false;
		} else if (!baseType.equals(other.baseType))
			return false;
		
		if (this.taintSubFields != other.taintSubFields)
			return false;
		if (this.arrayTaintType != other.arrayTaintType)
			return false;
		
		if (!Arrays.equals(fields, other.fields))
			return false;
		if (!Arrays.equals(fieldTypes, other.fieldTypes))
			return false;
		
		assert this.hashCode() == obj.hashCode();
		return true;
	}
	
	public boolean isStaticFieldRef(){
		return value == null && fields != null && fields.length > 0;
	}
	
	public boolean isInstanceFieldRef(){
		return value != null && fields != null && fields.length > 0;
	}
	
	public boolean isFieldRef() {
		return fields != null && fields.length > 0;
	}
	
	public boolean isLocal(){
		return value != null && value instanceof Local && (fields == null || fields.length == 0);
	}
	
	@Override
	public String toString(){
		String str = "";
		if(value != null)
			str += value.toString() +"(" + value.getType() +")";
		if (fields != null)
			for (int i = 0; i < fields.length; i++)
				if (fields[i] != null) {
					if (!str.isEmpty())
						str += " ";
					str += fields[i];
				}
		if (taintSubFields)
			str += " *";
		
		if (arrayTaintType == ArrayTaintType.ContentsAndLength)
			str += " <+length>";
		else if (arrayTaintType == ArrayTaintType.Length)
			str += " <length>";
		
		return str;
	}

	public AccessPath copyWithNewValue(Value val){
		return copyWithNewValue(val, baseType, false);
	}
	
	/**
	 * value val gets new base, fields are preserved.
	 * @param val The new base value
	 * @return This access path with the base replaced by the value given in
	 * the val parameter
	 */
	public AccessPath copyWithNewValue(Value val, Type newType,
			boolean cutFirstField){
		return copyWithNewValue(val, newType, cutFirstField, true);
	}
	
	/**
	 * value val gets new base, fields are preserved.
	 * @param val The new base value
	 * @param reduceBases True if circurlar types shall be reduced to bases
	 * @return This access path with the base replaced by the value given in
	 * the val parameter
	 */
	public AccessPath copyWithNewValue(Value val, Type newType,
			boolean cutFirstField, boolean reduceBases) {
		return copyWithNewValue(val, newType, cutFirstField,
				reduceBases, arrayTaintType);
	}
	
	/**
	 * value val gets new base, fields are preserved.
	 * @param val The new base value
	 * @param reduceBases True if circular types shall be reduced to bases
	 * @param arrayTaintType The way a tainted array shall be handled
	 * @return This access path with the base replaced by the value given in
	 * the val parameter
	 */
	public AccessPath copyWithNewValue(Value val, Type newType, boolean cutFirstField,
			boolean reduceBases, ArrayTaintType arrayTaintType) {
		if (this.value != null && this.value.equals(val)
				&& this.baseType.equals(newType)
				&& this.arrayTaintType == arrayTaintType)
			return this;
		
		return new AccessPath(val, fields, newType, fieldTypes, this.taintSubFields,
				cutFirstField, reduceBases, arrayTaintType);
	}
	
	@Override
	public AccessPath clone(){
		// The empty access path is a singleton
		if (this == emptyAccessPath)
			return this;

		AccessPath a = new AccessPath(value, fields, baseType, fieldTypes,
				taintSubFields, false, true, arrayTaintType);
		assert a.equals(this);
		return a;
	}

	public static AccessPath getEmptyAccessPath() {
		return emptyAccessPath;
	}
	
	public boolean isEmpty() {
		return value == null && (fields == null || fields.length == 0);
	}

	/**
	 * Checks whether this access path entails the given one, i.e. refers to all
	 * objects the other access path also refers to.
	 * @param a2 The other access path
	 * @return True if this access path refers to all objects the other access
	 * path also refers to
	 */
	public boolean entails(AccessPath a2) {
		if (this.isEmpty() || a2.isEmpty())
			return false;
		
		// If one of the access paths refers to an instance object and the other
		// one doesn't, there can't be an entailment
		if ((this.value != null && a2.value == null)
				|| (this.value == null && a2.value != null))
			return false;
		
		// There cannot be an entailment for two instance references with
		// different base objects
		if (this.value != null && !this.value.equals(a2.value))
			return false;
		
		if (this.fields != null && a2.fields != null) {
			// If this access path is deeper than the other one, it cannot entail it
			if (this.fields.length > a2.fields.length)
				return false;
			
			// Check the fields in detail
			for (int i = 0; i < this.fields.length; i++)
				if (!this.fields[i].equals(a2.fields[i]))
					return false;
		}
		return true;
	}
	
	/**
	 * Merges this access path with the given one, i.e., adds the fields of the
	 * given access path to this one.
	 * @param ap The access path whose fields to append to this one
	 * @return The new access path
	 */
	public AccessPath merge(AccessPath ap) {
		return appendFields(ap.fields, ap.fieldTypes, ap.taintSubFields);
	}
	
	/**
	 * Appends additional fields to this access path
	 * @param apFields The fields to append
	 * @param apFieldTypes The types of the fields to append
	 * @param taintSubFields True if the new access path shall taint all objects
	 * reachable through it, false if it shall only point to precisely one object
	 * @return The new access path
	 */
	public AccessPath appendFields(SootField[] apFields, Type[] apFieldTypes, boolean taintSubFields) {
		int offset = this.fields == null ? 0 : this.fields.length;
		SootField[] fields = new SootField[offset + (apFields == null ? 0 : apFields.length)];
		Type[] fieldTypes = new Type[offset + (apFields == null ? 0 : apFields.length)];
		if (this.fields != null) {
			System.arraycopy(this.fields, 0, fields, 0, this.fields.length);
			System.arraycopy(this.fieldTypes, 0, fieldTypes, 0, this.fieldTypes.length);
		}
		if (apFields != null && apFields.length > 0) {
			System.arraycopy(apFields, 0, fields, offset, apFields.length);
			System.arraycopy(apFieldTypes, 0, fieldTypes, offset, apFieldTypes.length);
		}
		
		return new AccessPath(this.value, fields, baseType, fieldTypes, taintSubFields,
				false, true, arrayTaintType);
	}
	
	/**
	 * Gets a copy of this access path, but drops the first field. If this
	 * access path has no fields, the identity is returned.
	 * @return A copy of this access path with the first field being dropped.
	 */
	public AccessPath dropFirstField() {
		if (fields == null || fields.length == 0)
			return this;
		
		final SootField[] newFields;
		final Type[] newTypes;
		if (fields.length > 1) {
			newFields = new SootField[fields.length - 1];
			System.arraycopy(fields, 1, newFields, 0, fields.length - 1);

			newTypes = new Type[fields.length - 1];
			System.arraycopy(fieldTypes, 1, newTypes, 0, fields.length - 1);
		}
		else {
			newFields = null;
			newTypes = null;
		}
		return new AccessPath(value, newFields, fieldTypes[0], newTypes, taintSubFields,
				false, true, arrayTaintType);		
	}
	
	/**
	 * Gets a copy of this access path, but drops the last field. If this
	 * access path has no fields, the identity is returned.
	 * @return A copy of this access path with the last field being dropped.
	 */
	public AccessPath dropLastField() {
		if (fields == null || fields.length == 0)
			return this;
		
		final SootField[] newFields;
		final Type[] newTypes;
		if (fields.length > 1) {
			newFields = new SootField[fields.length - 1];
			System.arraycopy(fields, 0, newFields, 0, fields.length - 1);

			newTypes = new Type[fields.length - 1];
			System.arraycopy(fieldTypes, 0, newTypes, 0, fields.length - 1);
		}
		else {
			newFields = null;
			newTypes = null;
		}
		return new AccessPath(value, newFields, baseType, newTypes,
				taintSubFields, arrayTaintType);
	}
	
	/**
	 * Gets the type of the base value
	 * @return The type of the base value
	 */
	public Type getBaseType() {
		return this.baseType;
	}
	
	/**
	 * Gets whether sub-fields shall be tainted. If this access path is e.g.
	 * a.b.*, the result is true, whereas it is false for a.b.
	 * @return True if this access path includes all objects rechable through
	 * it, otherwise false
	 */
	public boolean getTaintSubFields() {
		return this.taintSubFields;
	}
	
	/**
	 * Gets whether this access path has been (transitively) constructed from
	 * one which was cut off by the access path length limitation. If this is
	 * the case, this AP might not be precise.
	 * @return True if this access path was constructed from a cut-off one.
	 */
	public boolean isCutOffApproximation() {
		return this.cutOffApproximation;
	}
	
	/**
	 * Gets whether this access path references only the length of the array to
	 * which it points, not the contents of that array
	 * @return True if this access paths points refers to the length of an array
	 * instead of to its contents
	 */
	public ArrayTaintType getArrayTaintType() {
		return this.arrayTaintType;
	}
	
}
