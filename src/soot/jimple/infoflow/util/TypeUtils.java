package soot.jimple.infoflow.util;

import soot.ArrayType;
import soot.BooleanType;
import soot.PrimType;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.Type;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.data.AccessPath;

/**
 * Class containing various utility methods for dealing with type information
 * 
 * @author Steven Arzt
 *
 */
public class TypeUtils {
	
	private final InfoflowManager manager;
	
	public TypeUtils(InfoflowManager manager) {
		this.manager = manager;
	}
	
	/**
	 * Checks whether the given type is a string
	 * @param tp The type of check
	 * @return True if the given type is a string, otherwise false
	 */
	public static boolean isStringType(Type tp) {
		if (!(tp instanceof RefType))
			return false;
		RefType refType = (RefType) tp;
		return refType.getClassName().equals("java.lang.String");
	}
	
	/**
	 * Checks whether the given type is java.lang.Object, java.io.Serializable,
	 * or java.lang.Cloneable.
	 * @param tp The type to check
	 * @return True if the given type is one of the three "object-like" types,
	 * otherwise false
	 */
	public static boolean isObjectLikeType(Type tp) {
		if (!(tp instanceof RefType))
			return false;
		
		RefType rt = (RefType) tp;
		return rt.equals(Scene.v().getObjectType())
				|| rt.getSootClass().getName().equals("java.io.Serializable")
				|| rt.getSootClass().getName().equals("java.lang.Cloneable");
	}
	
	/**
	 * Checks whether the given source type can be cast to the given destination
	 * type
	 * @param destType The destination type to which to cast
	 * @param sourceType The source type from which to cast
	 * @return True if the given types are cast-compatible, otherwise false
	 */
	public boolean checkCast(Type destType, Type sourceType) {
		if (!manager.getConfig().getEnableTypeChecking())
			return true;
		
		// If we don't have a source type, we generally allow the cast
		if (sourceType == null)
			return true;
		
		// If both types are equal, we allow the cast
		if (sourceType == destType)
			return true;
		
		// If we have a reference type, we use the Soot hierarchy
		if (Scene.v().getFastHierarchy().canStoreType(destType, sourceType) // cast-up, i.e. Object to String
				|| Scene.v().getFastHierarchy().canStoreType(sourceType, destType)) // cast-down, i.e. String to Object
			return true;
		
		// If both types are primitive, they can be cast unless a boolean type
		// is involved
		if (destType instanceof PrimType && sourceType instanceof PrimType)
			if (destType != BooleanType.v() && sourceType != BooleanType.v())
				return true;
			
		return false;
	}
	
	/**
	 * Checks whether the type of the given taint can be cast to the given
	 * target type
	 * @param accessPath The access path of the taint to be cast
	 * @param type The target type to which to cast the taint
	 * @return True if the cast is possible, otherwise false
	 */
	public boolean checkCast(AccessPath accessPath, Type type) {
		if (!manager.getConfig().getEnableTypeChecking())
			return true;
		
		if (accessPath.isStaticFieldRef()) {
			if (!checkCast(type, accessPath.getFirstFieldType()))
				return false;
			
			// If the target type is a primitive array, we cannot have any
			// subsequent field
			if (isPrimitiveArray(type))
				return accessPath.getFieldCount() == 1;
			return true;
		}
		else {
			if (!checkCast(type, accessPath.getBaseType()))
				return false;
			// If the target type is a primitive array, we cannot have any
			// subsequent fields
			if (isPrimitiveArray(type))
				return accessPath.isLocal();
			return true;
		}
	}
	
	public static boolean isPrimitiveArray(Type type) {
		if (type instanceof ArrayType) {
			ArrayType at = (ArrayType) type;
			if (at.getArrayElementType() instanceof PrimType)
				return true;
		}
		return false;
	}
	
	public boolean hasCompatibleTypesForCall(AccessPath apBase, SootClass dest) {
		if (!manager.getConfig().getEnableTypeChecking())
			return true;
		
		// Cannot invoke a method on a primitive type
		if (apBase.getBaseType() instanceof PrimType)
			return false;
		// Cannot invoke a method on an array
		if (apBase.getBaseType() instanceof ArrayType)
			return dest.getName().equals("java.lang.Object");
		
		return Scene.v().getOrMakeFastHierarchy().canStoreType(apBase.getBaseType(), dest.getType())
				|| Scene.v().getOrMakeFastHierarchy().canStoreType(dest.getType(), apBase.getBaseType());
	}
	
}
