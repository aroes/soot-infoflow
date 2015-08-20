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
package soot.jimple.infoflow.problems;

import heros.FlowFunction;
import heros.FlowFunctions;
import heros.TwoElementSet;
import heros.flowfunc.Identity;
import heros.flowfunc.KillAll;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import soot.ArrayType;
import soot.BooleanType;
import soot.IntType;
import soot.Local;
import soot.NullType;
import soot.PrimType;
import soot.RefType;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.Constant;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.IdentityStmt;
import soot.jimple.IfStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InstanceOfExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.LengthExpr;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticFieldRef;
import soot.jimple.Stmt;
import soot.jimple.TableSwitchStmt;
import soot.jimple.ThrowStmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.aliasing.IAliasingStrategy;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.infoflow.collect.MyConcurrentHashMap;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.data.AccessPath.ArrayTaintType;
import soot.jimple.infoflow.handlers.TaintPropagationHandler;
import soot.jimple.infoflow.handlers.TaintPropagationHandler.FlowFunctionType;
import soot.jimple.infoflow.problems.rules.PropagationRuleManager;
import soot.jimple.infoflow.solver.functions.SolverCallFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverCallToReturnFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverNormalFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverReturnFlowFunction;
import soot.jimple.infoflow.source.SourceInfo;
import soot.jimple.infoflow.util.BaseSelector;
import soot.jimple.infoflow.util.ByReferenceBoolean;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.jimple.infoflow.util.TypeUtils;

public class InfoflowProblem extends AbstractInfoflowProblem {
	
	private final Aliasing aliasing;
	private final IAliasingStrategy aliasingStrategy;
	private final PropagationRuleManager propagationRules;
	
    private final MyConcurrentHashMap<Unit, Set<Abstraction>> implicitTargets =
    		new MyConcurrentHashMap<Unit, Set<Abstraction>>();
    
	protected final MyConcurrentHashMap<AbstractionAtSink, Abstraction> results =
			new MyConcurrentHashMap<AbstractionAtSink, Abstraction>();
	
	public InfoflowProblem(InfoflowManager manager,
			IAliasingStrategy aliasingStrategy,
			Abstraction zeroValue) {
		super(manager);
		
		if (zeroValue != null)
			setZeroValue(zeroValue);
		
		this.aliasingStrategy = aliasingStrategy;
		this.aliasing = new Aliasing(aliasingStrategy, manager.getICFG());
		
		this.propagationRules = new PropagationRuleManager(manager, aliasing, createZeroValue());
	}
	
	@Override
	public FlowFunctions<Unit, Abstraction, SootMethod> createFlowFunctionsFactory() {
		return new FlowFunctions<Unit, Abstraction, SootMethod>() {
			
			/**
			 * Abstract base class for all normal flow functions. This is to
			 * share code that e.g. notifies the taint handlers between the
			 * various functions.
			 * 
			 * @author Steven Arzt
			 */
			abstract class NotifyingNormalFlowFunction extends SolverNormalFlowFunction {
				
				private final Stmt stmt;
				
				public NotifyingNormalFlowFunction(Stmt stmt) {
					this.stmt = stmt;
				}
				
				@Override
				public Set<Abstraction> computeTargets(Abstraction d1, Abstraction source) {
					if (manager.getConfig().getStopAfterFirstFlow() && !results.isEmpty())
						return Collections.emptySet();
												
					// Notify the handler if we have one
					if (taintPropagationHandlers != null)
						for (TaintPropagationHandler tp : taintPropagationHandlers)
							tp.notifyFlowIn(stmt, source, interproceduralCFG(),
									FlowFunctionType.NormalFlowFunction);
					
					// Compute the new abstractions
					Set<Abstraction> res = computeTargetsInternal(d1, source);
					return notifyOutFlowHandlers(stmt, d1, source, res,
							FlowFunctionType.NormalFlowFunction);
				}
				
				public abstract Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source);

			}
			
			/**
			 * Notifies the outbound flow handlers, if any, about the computed
			 * result abstractions for the current flow function
			 * @param d1 The abstraction at the beginning of the method
			 * @param stmt The statement that has just been processed
			 * @param incoming The incoming abstraction from which the outbound
			 * ones were computed
			 * @param outgoing The outbound abstractions to be propagated on
			 * @param functionType The type of flow function that was computed
			 * @return The outbound flow abstracions, potentially changed by the
			 * flow handlers
			 */
			private Set<Abstraction> notifyOutFlowHandlers(Unit stmt,
					Abstraction d1,
					Abstraction incoming,
					Set<Abstraction> outgoing,
					FlowFunctionType functionType) {
				if (taintPropagationHandlers != null
						&& outgoing != null
						&& !outgoing.isEmpty())
					for (TaintPropagationHandler tp : taintPropagationHandlers)
						outgoing = tp.notifyFlowOut(stmt, d1, incoming, outgoing,
								interproceduralCFG(), functionType);
				return outgoing;
			}
			
			/**
			 * Taints the left side of the given assignment
			 * @param assignStmt The source statement from which the taint originated
			 * @param targetValue The target value that shall now be tainted
			 * @param source The incoming taint abstraction from the source
			 * @param taintSet The taint set to which to add all newly produced
			 * taints
			 */
			private void addTaintViaStmt
					(final Abstraction d1,
					final AssignStmt assignStmt,
					Abstraction source,
					Set<Abstraction> taintSet,
					boolean cutFirstField,
					SootMethod method,
					Type targetType,
					ArrayTaintType arrayTaintType) {
				final Value leftValue = assignStmt.getLeftOp();
				final Value rightValue = assignStmt.getRightOp();
				
				// Do not taint static fields unless the option is enabled
				if (!manager.getConfig().getEnableStaticFieldTracking()
						&& leftValue instanceof StaticFieldRef)
					return;
				
				Abstraction newAbs = null;
				if (!source.getAccessPath().isEmpty()) {
					// Special handling for array (de)construction
					if (leftValue instanceof ArrayRef && targetType != null)
						targetType = buildArrayOrAddDimension(targetType);
					else if (assignStmt.getRightOp() instanceof ArrayRef && targetType != null)
						targetType = ((ArrayType) targetType).getElementType();
					
					// If this is an unrealizable typecast, drop the abstraction
					if (rightValue instanceof CastExpr) {
						// If we cast java.lang.Object to an array type,
						// we must update our typing information
						CastExpr cast = (CastExpr) assignStmt.getRightOp();
						if (cast.getType() instanceof ArrayType && !(targetType instanceof ArrayType)) {
							assert canCastType(targetType, cast.getType());
							
							// If the cast was realizable, we can assume that we had the
							// type to which we cast.
							targetType = cast.getType();
						}
					}
					// Special type handling for certain operations
					else if (rightValue instanceof InstanceOfExpr)
						newAbs = source.deriveNewAbstraction(new AccessPath(leftValue, null,
								BooleanType.v(), (Type[]) null, true,
								ArrayTaintType.ContentsAndLength), assignStmt);
					else if (rightValue instanceof NewArrayExpr) {
						arrayTaintType = ArrayTaintType.Length;
						targetType = null;
					}
				}
				else
					// For implicit taints, we have no type information
					assert targetType == null;
				
				// also taint the target of the assignment
				if (newAbs == null)
					if (source.getAccessPath().isEmpty())
						newAbs = source.deriveNewAbstraction(new AccessPath(leftValue, true), assignStmt, true);
					else
						newAbs = source.deriveNewAbstraction(leftValue, cutFirstField, assignStmt, targetType,
								arrayTaintType);
				taintSet.add(newAbs);
				
				if (aliasing.canHaveAliases(assignStmt, leftValue, newAbs))
					aliasing.computeAliases(d1, assignStmt, leftValue, taintSet,
							method, newAbs);
			}
			
			/**
			 * Checks whether the given call has at least one valid target,
			 * i.e. a callee with a body.
			 * @param call The call site to check
			 * @return True if there is at least one callee implementation
			 * for the given call, otherwise false
			 */
			private boolean hasValidCallees(Unit call) {
				Collection<SootMethod> callees = interproceduralCFG().getCalleesOfCallAt(call);
				for (SootMethod callee : callees)
					if (callee.isConcrete())
						return true;
				return false;
			}

			@Override
			public FlowFunction<Abstraction> getNormalFlowFunction(final Unit src, final Unit dest) {
				// Get the call site
				if (!(src instanceof Stmt))
					return KillAll.v();
				final Stmt stmt = (Stmt) src;
				
				// If we compute flows on parameters, we create the initial
				// flow fact here
				if (src instanceof IdentityStmt) {
					final IdentityStmt is = (IdentityStmt) src;
					
					return new NotifyingNormalFlowFunction(is) {
						
						@Override
						public Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
							// Check whether we must leave a conditional branch
							if (source.isTopPostdominator(is)) {
								source = source.dropTopPostdominator();
								// Have we dropped the last postdominator for an empty taint?
								if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
									return Collections.emptySet();
							}
							
							// Compute the sources
							Set<Abstraction> res = propagationRules.applyNormalFlowFunction(d1, source, is, null);
							return res == null || res.isEmpty() ? Collections.<Abstraction>emptySet() : res;
						}
					};

				}

				// taint is propagated with assignStmt
				else if (src instanceof AssignStmt) {
					final AssignStmt assignStmt = (AssignStmt) src;
					final Value right = assignStmt.getRightOp();
					
					final Value leftValue = assignStmt.getLeftOp();
					final Value[] rightVals = BaseSelector.selectBaseList(right, true);
										
					return new NotifyingNormalFlowFunction(assignStmt) {
						
						@Override
						public Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
							// Make sure nothing all wonky is going on here
							assert source.getAccessPath().isEmpty()
									|| source.getTopPostdominator() == null;
							assert source.getTopPostdominator() == null
									|| interproceduralCFG().getMethodOf(src) == source.getTopPostdominator().getMethod()
									|| interproceduralCFG().getMethodOf(src).getActiveBody().getUnits().contains
											(source.getTopPostdominator().getUnit());
							
                            // on NormalFlow taint cannot be created
							ByReferenceBoolean killAll = new ByReferenceBoolean();
							Set<Abstraction> res = propagationRules.applyNormalFlowFunction(d1, source, stmt, killAll);
							if (killAll.value)
								return Collections.<Abstraction>emptySet();
							
							// Check whether we must leave a conditional branch
							if (source.isTopPostdominator(assignStmt)) {
								source = source.dropTopPostdominator();
								// Have we dropped the last postdominator for an empty taint?
								if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
									return Collections.emptySet();
							}
							
							// Check whether we must activate a taint
							final Abstraction newSource;
							if (!source.isAbstractionActive() && src == source.getActivationUnit())
								newSource = source.getActiveCopy();
							else
								newSource = source;
							
							// Create the new taints that may be created by this assignment
							Set<Abstraction> resAssign = createNewTaintOnAssignment(src, assignStmt,
									rightVals, d1, newSource);
							if (resAssign != null) {
								res.addAll(resAssign);
								return res;
							}
							
							// If we have propagated taint, we have returned from this method by now
							
							//if leftvalue contains the tainted value -> it is overwritten - remove taint:
							//but not for arrayRefs:
							// x[i] = y --> taint is preserved since we do not distinguish between elements of collections 
							//because we do not use a MUST-Alias analysis, we cannot delete aliases of taints 
							if (assignStmt.getLeftOp() instanceof ArrayRef)
								return Collections.singleton(newSource);
							
							if(newSource.getAccessPath().isInstanceFieldRef()) {
								// Data Propagation: x.f = y && x.f tainted --> no taint propagated
								// Alias Propagation: Only kill the alias if we directly overwrite it,
								// otherwise it might just be the creation of yet another alias
								if (leftValue instanceof InstanceFieldRef) {
									InstanceFieldRef leftRef = (InstanceFieldRef) leftValue;
									boolean baseAliases = source.isAbstractionActive()
											&& aliasing.mustAlias((Local) leftRef.getBase(),
													newSource.getAccessPath().getPlainValue(), assignStmt);
									if (baseAliases
											|| leftRef.getBase() == newSource.getAccessPath().getPlainValue()) {
										if (aliasing.mustAlias(leftRef.getField(), newSource.getAccessPath().getFirstField())) {
											return Collections.emptySet();
										}
									}
								}
								// x = y && x.f tainted -> no taint propagated. This must only check the precise
								// variable which gets replaced, but not any potential strong aliases
								else if (leftValue instanceof Local){
									if (leftValue == newSource.getAccessPath().getPlainValue()) {
										return Collections.emptySet();
									}
								}	
							}
							//X.f = y && X.f tainted -> no taint propagated. Kills are allowed even if
							// static field tracking is disabled
							else if (newSource.getAccessPath().isStaticFieldRef()){
								if(leftValue instanceof StaticFieldRef
										&& aliasing.mustAlias(((StaticFieldRef)leftValue).getField(),
												newSource.getAccessPath().getFirstField())){
									return Collections.emptySet();
								}
								
							}
							//when the fields of an object are tainted, but the base object is overwritten
							// then the fields should not be tainted any more
							//x = y && x.f tainted -> no taint propagated
							else if (newSource.getAccessPath().isLocal()
									&& leftValue instanceof Local
									&& leftValue == newSource.getAccessPath().getPlainValue()){
								return Collections.emptySet();
							}
														
							//nothing applies: z = y && x tainted -> taint is preserved
							return Collections.singleton(newSource);
						}

						private Set<Abstraction> createNewTaintOnAssignment(final Unit src,
								final AssignStmt assignStmt,
								final Value[] rightVals,
								Abstraction d1,
								final Abstraction newSource) {
							final Value leftValue = assignStmt.getLeftOp();
							final Value rightValue = assignStmt.getRightOp();
							boolean addLeftValue = false;
							
							// If we have an implicit flow, but the assigned
							// local is never read outside the condition, we do
							// not need to taint it.
							boolean implicitTaint = newSource.getTopPostdominator() != null
									&& newSource.getTopPostdominator().getUnit() != null;
							implicitTaint |= newSource.getAccessPath().isEmpty();
							
							// If we have a non-empty postdominator stack, we taint
							// every assignment target
							if (implicitTaint) {
								assert manager.getConfig().getEnableImplicitFlows();
								
								// We can skip over all local assignments inside conditionally-
								// called functions since they are not visible in the caller
								// anyway
								if ((d1 == null || d1.getAccessPath().isEmpty())
										&& !(leftValue instanceof FieldRef))
									return Collections.singleton(newSource);
																
								if (newSource.getAccessPath().isEmpty())
									addLeftValue = true;
							}
							
							// If we have a = x with the taint "x" being inactive,
							// we must not taint the left side. We can only taint
							// the left side if the tainted value is some "x.y".
							boolean aliasOverwritten = !addLeftValue
									&& !newSource.isAbstractionActive()
									&& Aliasing.baseMatchesStrict(rightValue, newSource)
									&& rightValue.getType() instanceof RefType
									&& !newSource.dependsOnCutAP();
							
							ArrayTaintType arrayTaintType = newSource.getAccessPath().getArrayTaintType();
							boolean cutFirstField = false;
							AccessPath mappedAP = newSource.getAccessPath();
							Type targetType = null;
							if (!addLeftValue && !aliasOverwritten) {
								for (Value rightVal : rightVals) {
									if (rightVal instanceof FieldRef) {
										// Get the field reference
										FieldRef rightRef = (FieldRef) rightVal;

										// If the right side references a NULL field, we kill the taint
										if (rightRef instanceof InstanceFieldRef
												&& ((InstanceFieldRef) rightRef).getBase().getType() instanceof NullType)
											return null;
										
										// Check for aliasing
										mappedAP = aliasing.mayAlias(newSource.getAccessPath(), rightRef);
										
										// check if static variable is tainted (same name, same class)
										//y = X.f && X.f tainted --> y, X.f tainted
										if (rightVal instanceof StaticFieldRef) {
											if (manager.getConfig().getEnableStaticFieldTracking() && mappedAP != null) {
												addLeftValue = true;
												cutFirstField = true;
											}
										}
										// check for field references
										//y = x.f && x tainted --> y, x tainted
										//y = x.f && x.f tainted --> y, x tainted
										else if (rightVal instanceof InstanceFieldRef) {								
											Local rightBase = (Local) ((InstanceFieldRef) rightRef).getBase();
											Local sourceBase = newSource.getAccessPath().getPlainValue();
											final SootField rightField = rightRef.getField();
											
											// We need to compare the access path on the right side
											// with the start of the given one
											if (mappedAP != null) {
												addLeftValue = true;
												cutFirstField = (mappedAP.getFieldCount() > 0
														&& mappedAP.getFirstField() == rightField);
											}
											else if (aliasing.mayAlias(rightBase, sourceBase)
													&& newSource.getAccessPath().getFieldCount() == 0
													&& newSource.getAccessPath().getTaintSubFields()) {
												addLeftValue = true;
												targetType = rightField.getType();
											}
										}
									}
									// indirect taint propagation:
									// if rightvalue is local and source is instancefield of this local:
									// y = x && x.f tainted --> y.f, x.f tainted
									// y.g = x && x.f tainted --> y.g.f, x.f tainted
									else if (rightVal instanceof Local && newSource.getAccessPath().isInstanceFieldRef()) {
										Local base = newSource.getAccessPath().getPlainValue();
										if (aliasing.mayAlias(rightVal, base)) {
											addLeftValue = true;
											targetType = newSource.getAccessPath().getBaseType();
										}
									}
									//y = x[i] && x tainted -> x, y tainted
									else if (rightVal instanceof ArrayRef) {
										Local rightBase = (Local) ((ArrayRef) rightVal).getBase();
										if (newSource.getAccessPath().getArrayTaintType() != ArrayTaintType.Length
												&& aliasing.mayAlias(rightBase, newSource.getAccessPath().getPlainValue())) {											
											addLeftValue = true;
											targetType = newSource.getAccessPath().getBaseType();
											assert targetType instanceof ArrayType;
										}
									}
									// generic case, is true for Locals, ArrayRefs that are equal etc..
									//y = x && x tainted --> y, x tainted
									else if (aliasing.mayAlias(rightVal, newSource.getAccessPath().getPlainValue())) {
										if (manager.getConfig().getEnableArraySizeTainting()
												|| !(rightVal instanceof NewArrayExpr)) {
											addLeftValue = true;
											targetType = newSource.getAccessPath().getBaseType();
										}
									}
									
									// One reason to taint the left side is enough
									if (addLeftValue)
										break;
								}
							}
							
							// If we have nothing to add, we quit
							if (!addLeftValue)
								return null;
							
							// Do not propagate non-active primitive taints
							if (!newSource.isAbstractionActive()
									&& (assignStmt.getLeftOp().getType() instanceof PrimType
											|| TypeUtils.isStringType(assignStmt.getLeftOp().getType())))
								return Collections.singleton(newSource);
							
							// If the right side is a typecast, it must be compatible,
							// or this path is not realizable
							if (rightValue instanceof CastExpr) {
								CastExpr ce = (CastExpr) rightValue;
								if (!checkCast(newSource.getAccessPath(), ce.getCastType()))
									return Collections.emptySet();
							}
							// Special handling for certain operations
							else if (rightValue instanceof LengthExpr) {
								// Check that we really have an array
								assert newSource.getAccessPath().isEmpty()
										|| newSource.getAccessPath().getBaseType() instanceof ArrayType;
								assert leftValue instanceof Local;
								
								// Is the length tainted?
								if (newSource.getAccessPath().getArrayTaintType() == ArrayTaintType.Contents)
									return Collections.singleton(newSource);
								
								// Taint the array length
								AccessPath ap = new AccessPath(leftValue, null, IntType.v(),
										(Type[]) null, true, false, true, ArrayTaintType.ContentsAndLength);
								Abstraction lenAbs = newSource.deriveNewAbstraction(ap, assignStmt);
								return new TwoElementSet<Abstraction>(newSource, lenAbs);
							}
							
							// Do we taint the contents of an array?
							if (leftValue instanceof ArrayRef)
								arrayTaintType = ArrayTaintType.Contents;
							
							// If this is a sink, we need to report the finding
							if (manager.getSourceSinkManager() != null
									&& manager.getSourceSinkManager().isSink(stmt, interproceduralCFG(),
											newSource.getAccessPath())
									&& newSource.isAbstractionActive()
									&& newSource.getAccessPath().isEmpty())
								addResult(new AbstractionAtSink(newSource, assignStmt));
							
							Set<Abstraction> res = new HashSet<Abstraction>();
							Abstraction targetAB = mappedAP.equals(newSource.getAccessPath())
									? newSource : newSource.deriveNewAbstraction(mappedAP, null);							
							addTaintViaStmt(d1, assignStmt, targetAB, res, cutFirstField,
									interproceduralCFG().getMethodOf(src), targetType,
									arrayTaintType);
							res.add(newSource);
							return res;
						}
					};
				}
				// for unbalanced problems, return statements correspond to
				// normal flows, not return flows, because there is no return
				// site we could jump to
				else if (src instanceof ReturnStmt) {
					final ReturnStmt returnStmt = (ReturnStmt) src;
					return new NotifyingNormalFlowFunction(returnStmt) {
						
						@Override
						public Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
							// Check whether we must leave a conditional branch
							if (source.isTopPostdominator(returnStmt)) {
								source = source.dropTopPostdominator();
								// Have we dropped the last postdominator for an empty taint?
								if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
									return Collections.emptySet();
							}
							
							// Check whether we have reached a sink
							if (manager.getSourceSinkManager() != null
									&& source.isAbstractionActive()
									&& aliasing.mayAlias(returnStmt.getOp(), source.getAccessPath().getPlainValue())
									&& manager.getSourceSinkManager().isSink(returnStmt, interproceduralCFG(),
											source.getAccessPath()))
								addResult(new AbstractionAtSink(source, returnStmt));

							return Collections.singleton(source);
						}
					};
				}
				else if (src instanceof ThrowStmt) {
					final ThrowStmt throwStmt = (ThrowStmt) src;
					return new NotifyingNormalFlowFunction(throwStmt) {

						@Override
						public Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
							// Check whether we must leave a conditional branch
							if (source.isTopPostdominator(throwStmt)) {
								source = source.dropTopPostdominator();
								// Have we dropped the last postdominator for an empty taint?
								if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
									return Collections.emptySet();
							}
							
							Set<Abstraction> res = propagationRules.applyNormalFlowFunction(d1, source, throwStmt, null);
							return res == null || res.isEmpty() ? Collections.<Abstraction>emptySet() : res;
						}
					};
				}
				// IF statements can lead to implicit flows or sinks
				else if (src instanceof IfStmt
						|| src instanceof LookupSwitchStmt
						|| src instanceof TableSwitchStmt) {
					final Value condition = src instanceof IfStmt ? ((IfStmt) src).getCondition()
							: src instanceof LookupSwitchStmt ? ((LookupSwitchStmt) src).getKey()
							: ((TableSwitchStmt) src).getKey();
					
					// Check for implicit flows
					return new NotifyingNormalFlowFunction(stmt) {

						@Override
						public Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
							// Check for a sink
							if (source.isAbstractionActive()
									&& manager.getSourceSinkManager() != null
									&& manager.getSourceSinkManager().isSink(stmt, interproceduralCFG(),
											source.getAccessPath()))
								for (Value v : BaseSelector.selectBaseList(condition, false))
									if (aliasing.mayAlias(v, source.getAccessPath().getPlainValue())) {
										addResult(new AbstractionAtSink(source, stmt));
										break;
									}
							
							Set<Abstraction> res = propagationRules.applyNormalFlowFunction(d1, source, stmt, null);
							return res == null || res.isEmpty() ? Collections.<Abstraction>emptySet() : res;
						}
					};
				}
				return Identity.v();
			}

			@Override
			public FlowFunction<Abstraction> getCallFlowFunction(final Unit src, final SootMethod dest) {
                if (!dest.isConcrete()){
                    logger.debug("Call skipped because target has no body: {} -> {}", src, dest);
                    return KillAll.v();
                }
                
				final Stmt stmt = (Stmt) src;
				final InvokeExpr ie = (stmt != null && stmt.containsInvokeExpr())
						? stmt.getInvokeExpr() : null;
				
				final Local[] paramLocals = dest.getActiveBody().getParameterLocals().toArray(
						new Local[0]);
				
				final SourceInfo sourceInfo = manager.getSourceSinkManager() != null
						? manager.getSourceSinkManager().getSourceInfo(stmt, interproceduralCFG()) : null;
				final boolean isSink = manager.getSourceSinkManager() != null
						? manager.getSourceSinkManager().isSink(stmt, interproceduralCFG(), null) : false;
				
				// This is not cached by Soot, so accesses are more expensive
				// than one might think
				final Local thisLocal = dest.isStatic() ? null : dest.getActiveBody().getThisLocal();
				
				return new SolverCallFlowFunction() {

					@Override
					public Set<Abstraction> computeTargets(Abstraction d1, Abstraction source) {
						Set<Abstraction> res = computeTargetsInternal(d1, source);
						if (!res.isEmpty())
							for (Abstraction abs : res)
								aliasingStrategy.injectCallingContext(abs, solver, dest, src, source, d1);
						return notifyOutFlowHandlers(stmt, d1, source, res,
								FlowFunctionType.CallFlowFunction);
					}
					
					private Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
						if (manager.getConfig().getStopAfterFirstFlow() && !results.isEmpty())
							return Collections.emptySet();
						
						//if we do not have to look into sources or sinks:
						if (!manager.getConfig().getInspectSources() && sourceInfo != null)
							return Collections.emptySet();
						if (!manager.getConfig().getInspectSinks() && isSink)
							return Collections.emptySet();
						if (source == getZeroValue()) {
							assert sourceInfo != null;
							return Collections.singleton(source);
						}
						
						// Notify the handler if we have one
						if (taintPropagationHandlers != null)
							for (TaintPropagationHandler tp : taintPropagationHandlers)
								tp.notifyFlowIn(stmt, source, interproceduralCFG(),
										FlowFunctionType.CallFlowFunction);
						
						ByReferenceBoolean killAll = new ByReferenceBoolean();
						Set<Abstraction> res = propagationRules.applyCallFlowFunction(d1,
								source, stmt, killAll);
						if (killAll.value)
							return Collections.emptySet();
						if (res == null)
							res = new HashSet<Abstraction>();
						
						// Check whether we must leave a conditional branch
						if (source.isTopPostdominator(stmt)) {
							source = source.dropTopPostdominator();
							// Have we dropped the last postdominator for an empty taint?
							if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
								return Collections.emptySet();
						}
						
						// If no parameter is tainted, but we are in a conditional, we create a
						// pseudo abstraction. We do not map parameters if we are handling an
						// implicit flow anyway.
						if (source.getAccessPath().isEmpty()) {
							assert manager.getConfig().getEnableImplicitFlows();
							
							// Block the call site for further explicit tracking
							if (d1 != null) {
								Set<Abstraction> callSites = implicitTargets.putIfAbsentElseGet
										(src, new ConcurrentHashSet<Abstraction>());
								callSites.add(d1);
							}
							
							Abstraction abs = source.deriveConditionalAbstractionCall(src);
							return Collections.singleton(abs);
						}
						else if (source.getTopPostdominator() != null)
							return Collections.emptySet();
						
						// If we have already tracked implicit flows through this method,
						// there is no point in tracking explicit ones afterwards as well.
						if (implicitTargets.containsKey(src) && (d1 == null || implicitTargets.get(src).contains(d1)))
							return Collections.emptySet();
						
						// Only propagate the taint if the target field is actually read
						if (source.getAccessPath().isStaticFieldRef()
								&& !manager.getConfig().getEnableStaticFieldTracking())
							return Collections.emptySet();
						
						// Map the source access path into the callee
						Set<AccessPath> resMapping = mapAccessPathToCallee(dest, ie, paramLocals,
								thisLocal, source.getAccessPath());
						if (resMapping == null)
							return res;
						
						// Translate the access paths into abstractions
						Set<Abstraction> resAbs = new HashSet<Abstraction>(resMapping.size());
						resAbs.addAll(res);
						for (AccessPath ap : resMapping)
							if (ap.isStaticFieldRef()) {
								// Do not propagate static fields that are not read inside the callee 
								if (interproceduralCFG().isStaticFieldRead(dest, ap.getFirstField()))
									resAbs.add(source.deriveNewAbstraction(ap, stmt));
							}
							// If the variable is never read in the callee, there is no
							// need to propagate it through
							else if (source.isImplicit() || interproceduralCFG().methodReadsValue(dest, ap.getPlainValue()))
								resAbs.add(source.deriveNewAbstraction(ap, stmt));
						
						return resAbs;
					}
				};
			}

			@Override
			public FlowFunction<Abstraction> getReturnFlowFunction(final Unit callSite,
					final SootMethod callee, final Unit exitStmt, final Unit retSite) {
				// Get the call site
				if (callSite != null && !(callSite instanceof Stmt))
					return KillAll.v();
				final Stmt iCallStmt = (Stmt) callSite;
				
				final ReturnStmt returnStmt = (exitStmt instanceof ReturnStmt) ? (ReturnStmt) exitStmt : null;
				
				final Local[] paramLocals = callee.getActiveBody().getParameterLocals().toArray(
						new Local[0]);
				
				// This is not cached by Soot, so accesses are more expensive
				// than one might think
				final Local thisLocal = callee.isStatic() ? null : callee.getActiveBody().getThisLocal();	
				
				return new SolverReturnFlowFunction() {

					@Override
					public Set<Abstraction> computeTargets(Abstraction source, Abstraction d1,
							Collection<Abstraction> callerD1s) {
						Set<Abstraction> res = computeTargetsInternal(source, callerD1s);
						return notifyOutFlowHandlers(exitStmt, d1, source, res,
								FlowFunctionType.ReturnFlowFunction);
					}
					
					private Set<Abstraction> computeTargetsInternal(Abstraction source,
							Collection<Abstraction> callerD1s) {
						if (manager.getConfig().getStopAfterFirstFlow() && !results.isEmpty())
							return Collections.emptySet();
						if (source == getZeroValue())
							return Collections.emptySet();
						
						// Notify the handler if we have one
						if (taintPropagationHandlers != null)
							for (TaintPropagationHandler tp : taintPropagationHandlers)
								tp.notifyFlowIn(exitStmt, source, interproceduralCFG(),
										FlowFunctionType.ReturnFlowFunction);
						
						boolean callerD1sConditional = false;
						for (Abstraction d1 : callerD1s)
							if (d1.getAccessPath().isEmpty()) {
								callerD1sConditional = true;
								break;
							}
						
						// Activate taint if necessary
						Abstraction newSource = source;
						if(!source.isAbstractionActive())
							if(callSite != null)
								if (callSite == source.getActivationUnit()
										|| isCallSiteActivatingTaint(callSite, source.getActivationUnit()))
									newSource = source.getActiveCopy();
						
						// Empty access paths are never propagated over return edges
						if (source.getAccessPath().isEmpty()) {
							// If we return a constant, we must taint it
							if (returnStmt != null && returnStmt.getOp() instanceof Constant)
								if (callSite instanceof DefinitionStmt) {
									DefinitionStmt def = (DefinitionStmt) callSite;
									Abstraction abs = newSource.deriveNewAbstraction
											(newSource.getAccessPath().copyWithNewValue(def.getLeftOp()), (Stmt) exitStmt);

									Set<Abstraction> res = new HashSet<Abstraction>();
									res.add(abs);
									
									// If we taint a return value because it is implicit,
									// we must trigger an alias analysis
									if(aliasing.canHaveAliases(def, def.getLeftOp(), abs) && !callerD1sConditional)
										for (Abstraction d1 : callerD1s)
											aliasing.computeAliases(d1, iCallStmt, def.getLeftOp(), res,
													interproceduralCFG().getMethodOf(callSite), abs);
									return res;
								}
							
							// Kill the empty abstraction
							return Collections.emptySet();
						}

						// Are we still inside a conditional? We check this before we
						// leave the method since the return value is still assigned
						// inside the method.
						boolean insideConditional = newSource.getTopPostdominator() != null
								|| newSource.getAccessPath().isEmpty();

						// Check whether we must leave a conditional branch
						if (newSource.isTopPostdominator(exitStmt) || newSource.isTopPostdominator(callee)) {
							newSource = newSource.dropTopPostdominator();
							// Have we dropped the last postdominator for an empty taint?
							if (!insideConditional
									&& newSource.getAccessPath().isEmpty()
									&& newSource.getTopPostdominator() == null)
								return Collections.emptySet();
						}
												
						//if abstraction is not active and activeStmt was in this method, it will not get activated = it can be removed:
						if(!newSource.isAbstractionActive() && newSource.getActivationUnit() != null)
							if (interproceduralCFG().getMethodOf(newSource.getActivationUnit()) == callee)
								return Collections.emptySet();
						
						// Static field tracking can be disabled
						if (!manager.getConfig().getEnableStaticFieldTracking()
								&& newSource.getAccessPath().isStaticFieldRef())
							return Collections.emptySet();
												
						// Check whether this return is treated as a sink
						if (returnStmt != null) {
							assert returnStmt.getOp() == null
									|| returnStmt.getOp() instanceof Local
									|| returnStmt.getOp() instanceof Constant;
							
							boolean mustTaintSink = insideConditional;
							mustTaintSink |= returnStmt.getOp() != null
									&& newSource.getAccessPath().isLocal()
									&& aliasing.mayAlias(newSource.getAccessPath().getPlainValue(), returnStmt.getOp());
							if (mustTaintSink
									&& manager.getSourceSinkManager() != null
									&& manager.getSourceSinkManager().isSink(returnStmt, interproceduralCFG(),
											newSource.getAccessPath())
									&& newSource.isAbstractionActive())
								addResult(new AbstractionAtSink(newSource, returnStmt));
						}
						
						// If we have no caller, we have nowhere to propagate. This
						// can happen when leaving the main method.
						if (callSite == null)
							return Collections.emptySet();
						
						Set<Abstraction> res = propagationRules.applyReturnFlowFunction(callerD1s,
								newSource, (Stmt) exitStmt);
						if (res == null)
							res = new HashSet<Abstraction>();
						
						// if we have a returnStmt we have to look at the returned value:
						if (returnStmt != null && callSite instanceof DefinitionStmt) {
							Value retLocal = returnStmt.getOp();
							DefinitionStmt defnStmt = (DefinitionStmt) callSite;
							Value leftOp = defnStmt.getLeftOp();
							
							if ((insideConditional && leftOp instanceof FieldRef)
									|| aliasing.mayAlias(retLocal, newSource.getAccessPath().getPlainValue())) {
								Abstraction abs = newSource.deriveNewAbstraction
										(newSource.getAccessPath().copyWithNewValue(leftOp), (Stmt) exitStmt);
								res.add(abs);
								
								// Aliases of implicitly tainted variables must be mapped back
								// into the caller's context on return when we leave the last
								// implicitly-called method
								if ((abs.isImplicit()
										&& (abs.getAccessPath().isInstanceFieldRef() || abs.getAccessPath().isStaticFieldRef())
										&& !callerD1sConditional) || aliasingStrategy.requiresAnalysisOnReturn())
									for (Abstraction d1 : callerD1s)
										aliasing.computeAliases(d1, iCallStmt, leftOp, res,
												interproceduralCFG().getMethodOf(callSite), abs);
							}
						}

						// easy: static
						if (newSource.getAccessPath().isStaticFieldRef()) {
							// Simply pass on the taint
							Abstraction abs = newSource;
							res.add(abs);

							// Aliases of implicitly tainted variables must be mapped back
							// into the caller's context on return when we leave the last
							// implicitly-called method
							if ((abs.isImplicit() && !callerD1sConditional)
									 || aliasingStrategy.requiresAnalysisOnReturn())
								for (Abstraction d1 : callerD1s)
									aliasing.computeAliases(d1, iCallStmt, null, res,
											interproceduralCFG().getMethodOf(callSite), abs);
						}
						
						// checks: this/params/fields
						
						// check one of the call params are tainted (not if simple type)
						Value sourceBase = newSource.getAccessPath().getPlainValue();
						boolean parameterAliases = false;
						{
						Value originalCallArg = null;
						for (int i = 0; i < callee.getParameterCount(); i++) {
							// If this parameter is overwritten, we cannot propagate
							// the "old" taint over. Return value propagation must
							// always happen explicitly.
							if (callSite instanceof DefinitionStmt) {
								DefinitionStmt defnStmt = (DefinitionStmt) callSite;
								Value leftOp = defnStmt.getLeftOp();
								originalCallArg = defnStmt.getInvokeExpr().getArg(i);
								if (originalCallArg == leftOp)
									continue;
							}
							
							// Propagate over the parameter taint
							if (aliasing.mayAlias(paramLocals[i], sourceBase)) {
								parameterAliases = true;
								originalCallArg = iCallStmt.getInvokeExpr().getArg(i);
								
								// If this is a constant parameter, we can safely ignore it
								if (!AccessPath.canContainValue(originalCallArg))
									continue;
								if (!checkCast(source.getAccessPath(), originalCallArg.getType()))
									continue;
								
								// Primitive types and strings cannot have aliases and thus
								// never need to be propagated back
								if (source.getAccessPath().getBaseType() instanceof PrimType)
									continue;
								if (TypeUtils.isStringType(source.getAccessPath().getBaseType()))
									continue;
								
								Abstraction abs = newSource.deriveNewAbstraction
										(newSource.getAccessPath().copyWithNewValue(originalCallArg), (Stmt) exitStmt);
								res.add(abs);
								
								// Aliases of implicitly tainted variables must be mapped back
								// into the caller's context on return when we leave the last
								// implicitly-called method
								if ((abs.isImplicit()
										&& !callerD1sConditional) || aliasingStrategy.requiresAnalysisOnReturn()) {
									assert originalCallArg.getType() instanceof ArrayType
											|| originalCallArg.getType() instanceof RefType;
									for (Abstraction d1 : callerD1s)
										aliasing.computeAliases(d1, iCallStmt, originalCallArg, res,
											interproceduralCFG().getMethodOf(callSite), abs);
								}
							}
						}
						}

						
						{
						if (!callee.isStatic()) {
							if (aliasing.mayAlias(thisLocal, sourceBase)) {
								// check if it is not one of the params (then we have already fixed it)
								if (!parameterAliases) {
									if (iCallStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
										InstanceInvokeExpr iIExpr = (InstanceInvokeExpr) iCallStmt.getInvokeExpr();
										Abstraction abs = newSource.deriveNewAbstraction
												(newSource.getAccessPath().copyWithNewValue(iIExpr.getBase()), (Stmt) exitStmt);
										res.add(abs);
										
										// Aliases of implicitly tainted variables must be mapped back
										// into the caller's context on return when we leave the last
										// implicitly-called method
										if ((abs.isImplicit()
												&& aliasing.canHaveAliases(iCallStmt, iIExpr.getBase(), abs)
												&& !callerD1sConditional) || aliasingStrategy.requiresAnalysisOnReturn())
											for (Abstraction d1 : callerD1s)
												aliasing.computeAliases(d1, iCallStmt, iIExpr.getBase(), res,
														interproceduralCFG().getMethodOf(callSite), abs);											
									}
								}
							}
							}
						}
						
						for (Abstraction abs : res)
							if (abs != newSource)
								abs.setCorrespondingCallSite(iCallStmt);
						
						return res;
					}

				};
			}
			
			@Override
			public FlowFunction<Abstraction> getCallToReturnFlowFunction(final Unit call,
					final Unit returnSite) {
				// special treatment for native methods:
				if (!(call instanceof Stmt))
					return KillAll.v();
				
				final Stmt iCallStmt = (Stmt) call;
				final InvokeExpr invExpr = iCallStmt.getInvokeExpr();
				
				final Value[] callArgs = new Value[invExpr.getArgCount()];
				for (int i = 0; i < invExpr.getArgCount(); i++)
					callArgs[i] = invExpr.getArg(i);
				
				final boolean isSink = (manager.getSourceSinkManager() != null)
						? manager.getSourceSinkManager().isSink(iCallStmt, interproceduralCFG(), null) : false;
				
				final SootMethod callee = invExpr.getMethod();
				final boolean hasValidCallees = hasValidCallees(call);
				
				return new SolverCallToReturnFlowFunction() {

					@Override
					public Set<Abstraction> computeTargets(Abstraction d1, Abstraction source) {
						Set<Abstraction> res = computeTargetsInternal(d1, source);
						return notifyOutFlowHandlers(call, d1, source, res,
								FlowFunctionType.CallToReturnFlowFunction);
					}
					
					private Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source) {
						if (manager.getConfig().getStopAfterFirstFlow() && !results.isEmpty())
							return Collections.emptySet();
						
						// Notify the handler if we have one
						if (taintPropagationHandlers != null)
							for (TaintPropagationHandler tp : taintPropagationHandlers)
								tp.notifyFlowIn(call, source, interproceduralCFG(),
										FlowFunctionType.CallToReturnFlowFunction);
						
						// Check whether we must leave a conditional branch
						if (source.isTopPostdominator(call)) {
							source = source.dropTopPostdominator();
							// Have we dropped the last postdominator for an empty taint?
							if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null)
								return Collections.emptySet();
						}
						
						// Static field tracking can be disabled
						if (!manager.getConfig().getEnableStaticFieldTracking()
								&& source.getAccessPath().isStaticFieldRef())
							return Collections.emptySet();
						
						//check inactive elements:
						final Abstraction newSource;
						if (!source.isAbstractionActive() && (call == source.getActivationUnit()
								|| isCallSiteActivatingTaint(call, source.getActivationUnit())))
							newSource = source.getActiveCopy();
						else
							newSource = source;
						
						ByReferenceBoolean killSource = new ByReferenceBoolean();
						Set<Abstraction> res = propagationRules.applyCallToReturnFlowFunction(
								d1, newSource, iCallStmt, killSource, true);
						boolean passOn = !killSource.value;
						
						// Do not propagate zero abstractions
						if (source == getZeroValue())
							return res == null || res.isEmpty() ? Collections.<Abstraction>emptySet() : res;
						
						// Initialize the result set
						if (res == null)
							res = new HashSet<>();
						
						// if we have called a sink we have to store the path from the source - in case one of the params is tainted!
						if (manager.getSourceSinkManager() != null
								&& manager.getSourceSinkManager().isSink(iCallStmt, interproceduralCFG(),
										newSource.getAccessPath())) {
							// If we are inside a conditional branch, we consider every sink call a leak
							boolean conditionalCall = manager.getConfig().getEnableImplicitFlows() 
									&& !interproceduralCFG().getMethodOf(call).isStatic()
									&& aliasing.mayAlias(interproceduralCFG().getMethodOf(call).getActiveBody().getThisLocal(),
											newSource.getAccessPath().getPlainValue())
									&& newSource.getAccessPath().getFirstField() == null;
							boolean taintedParam = (conditionalCall
										|| newSource.getTopPostdominator() != null
										|| newSource.getAccessPath().isEmpty())
									&& newSource.isAbstractionActive();
							
							// If the base object is tainted, we also consider the "code" associated
							// with the object's class as tainted.
							if (!taintedParam) {
								for (int i = 0; i < callArgs.length; i++) {
									if (aliasing.mayAlias(callArgs[i], newSource.getAccessPath().getPlainValue())) {
										taintedParam = true;
										break;
									}
								}
							}
							
							if (taintedParam && newSource.isAbstractionActive())
								addResult(new AbstractionAtSink(newSource, iCallStmt));
							
							// if the base object which executes the method is tainted the sink is reached, too.
							if (invExpr instanceof InstanceInvokeExpr) {
								InstanceInvokeExpr vie = (InstanceInvokeExpr) iCallStmt.getInvokeExpr();
								if (newSource.isAbstractionActive()
										&& aliasing.mayAlias(vie.getBase(), newSource.getAccessPath().getPlainValue()))
									addResult(new AbstractionAtSink(newSource, iCallStmt));
							}
						}
						
						if (newSource.getTopPostdominator() != null
								&& newSource.getTopPostdominator().getUnit() == null)
							return Collections.singleton(newSource);
						
						// Implicit flows: taint return value
						if (call instanceof DefinitionStmt) {
							// If we have an implicit flow, but the assigned
							// local is never read outside the condition, we do
							// not need to taint it.
							boolean implicitTaint = newSource.getTopPostdominator() != null
									&& newSource.getTopPostdominator().getUnit() != null;							
							implicitTaint |= newSource.getAccessPath().isEmpty();
							
							if (implicitTaint) {
								Value leftVal = ((DefinitionStmt) call).getLeftOp();
								
								// We can skip over all local assignments inside conditionally-
								// called functions since they are not visible in the caller
								// anyway
								if ((d1 == null || d1.getAccessPath().isEmpty())
										&& !(leftVal instanceof FieldRef))
									return Collections.singleton(newSource);
								
								Abstraction abs = newSource.deriveNewAbstraction(new AccessPath(leftVal, true),
										iCallStmt);
								return new TwoElementSet<Abstraction>(newSource, abs);
							}
						}
						
						// If this call overwrites the left side, the taint is never passed on.
						if (passOn) {
							if (newSource.getAccessPath().isStaticFieldRef())
								passOn = false;
							else if (call instanceof DefinitionStmt
									&& aliasing.mayAlias(((DefinitionStmt) call).getLeftOp(),
											newSource.getAccessPath().getPlainValue()))
								passOn = false;
						}
						
						//we only can remove the taint if we step into the call/return edges
						//otherwise we will loose taint - see ArrayTests/arrayCopyTest
						if (passOn
								&& invExpr instanceof InstanceInvokeExpr
								&& newSource.getAccessPath().isInstanceFieldRef()
								&& (manager.getConfig().getInspectSinks() || !isSink)
								&& (hasValidCallees
									|| (taintWrapper != null && taintWrapper.isExclusive(
											iCallStmt, newSource)))) {
							// If one of the callers does not read the value, we must pass it on
							// in any case
							boolean allCalleesRead = true;
							outer : for (SootMethod callee : interproceduralCFG().getCalleesOfCallAt(call)) {
								if (callee.isConcrete() && callee.hasActiveBody()) {
									Set<AccessPath> calleeAPs = mapAccessPathToCallee(callee,
											invExpr, null, null, source.getAccessPath());
									if (calleeAPs != null)
										for (AccessPath ap : calleeAPs)
											if (!interproceduralCFG().methodReadsValue(callee, ap.getPlainValue())) {
												allCalleesRead = false;
												break outer;
											}
										}
							}
							
							if (allCalleesRead) {
								if (aliasing.mayAlias(((InstanceInvokeExpr) invExpr).getBase(),
										newSource.getAccessPath().getPlainValue())) {
									passOn = false;
								}
								if (passOn)
									for (int i = 0; i < callArgs.length; i++)
										if (aliasing.mayAlias(callArgs[i], newSource.getAccessPath().getPlainValue())) {
											passOn = false;
											break;
										}
								//static variables are always propagated if they are not overwritten. So if we have at least one call/return edge pair,
								//we can be sure that the value does not get "lost" if we do not pass it on:
								if(newSource.getAccessPath().isStaticFieldRef())
									passOn = false;
							}
						}
						
						// If the callee does not read the given value, we also need to pass it on
						// since we do not propagate it into the callee.
						if (source.getAccessPath().isStaticFieldRef()) {
							if (!interproceduralCFG().isStaticFieldUsed(callee,
									source.getAccessPath().getFirstField()))
								passOn = true;
						}
												
						// Implicit taints are always passed over conditionally called methods
						passOn |= source.getTopPostdominator() != null || source.getAccessPath().isEmpty();
						if (passOn) {
							if (newSource != getZeroValue())
								res.add(newSource);
						}
						
						if (callee.isNative())
							for (Value callVal : callArgs)
								if (callVal == newSource.getAccessPath().getPlainValue()) {
									// java uses call by value, but fields of complex objects can be changed (and tainted), so use this conservative approach:
									Set<Abstraction> nativeAbs = ncHandler.getTaintedValues(iCallStmt, newSource, callArgs);
									if (nativeAbs != null) {
										res.addAll(nativeAbs);
										
										// Compute the aliases
										for (Abstraction abs : nativeAbs)
											if (abs.getAccessPath().isStaticFieldRef()
													|| aliasing.canHaveAliases(iCallStmt,
															abs.getAccessPath().getPlainValue(), abs))
												aliasing.computeAliases(d1, iCallStmt,
														abs.getAccessPath().getPlainValue(), res,
														interproceduralCFG().getMethodOf(call), abs);
									}
									
									// We only call the native code handler once per statement
									break;
								}
						
						for (Abstraction abs : res)
							if (abs != newSource)
								abs.setCorrespondingCallSite(iCallStmt);
						
						return res;
					}
				};
			}
			
			/**
			 * Maps the given access path into the scope of the callee
			 * @param callee The method that is being called
			 * @param ie The invocation expression for the call
			 * @param paramLocals The list of parameter locals in the callee
			 * @param thisLocal The "this" local in the callee
			 * @param ap The caller-side access path to map
			 * @return The set of callee-side access paths corresponding to the
			 * given caller-side access path
			 */
			private Set<AccessPath> mapAccessPathToCallee(final SootMethod callee, final InvokeExpr ie,
					Value[] paramLocals, Local thisLocal, AccessPath ap) {
				// We do not transfer empty access paths
				if (ap.isEmpty())
					return Collections.emptySet();
				
				// Android executor methods are handled specially. getSubSignature()
				// is slow, so we try to avoid it whenever we can
				final boolean isExecutorExecute = isExecutorExecute(ie, callee);
				
				Set<AccessPath> res = null;
				
				// check if whole object is tainted (happens with strings, for example:)
				if (!isExecutorExecute
						&& !ap.isStaticFieldRef()
						&& !callee.isStatic()) {
					assert ie instanceof InstanceInvokeExpr;
					InstanceInvokeExpr vie = (InstanceInvokeExpr) ie;
					// this might be enough because every call must happen with a local variable which is tainted itself:
					if (aliasing.mayAlias(vie.getBase(), ap.getPlainValue()))
						if (hasCompatibleTypesForCall(ap, callee.getDeclaringClass())) {
							if (res == null) res = new HashSet<AccessPath>();
							
							// Get the "this" local if we don't have it yet
							if (thisLocal == null)
								thisLocal = callee.isStatic() ? null : callee.getActiveBody().getThisLocal();
							
							res.add(ap.copyWithNewValue(thisLocal));
						}
				}
				// staticfieldRefs must be analyzed even if they are not part of the params:
				else if (ap.isStaticFieldRef()) {
					if (res == null) res = new HashSet<AccessPath>();
					res.add(ap);
				}
				
				//special treatment for clinit methods - no param mapping possible
				if (isExecutorExecute) {
					if (aliasing.mayAlias(ie.getArg(0), ap.getPlainValue())) {
						if (res == null) res = new HashSet<AccessPath>();
						res.add(ap.copyWithNewValue(callee.getActiveBody().getThisLocal()));
					}
				}
				else if (callee.getParameterCount() > 0) {
					assert callee.getParameterCount() == ie.getArgCount();
					// check if param is tainted:
					for (int i = 0; i < ie.getArgCount(); i++) {
						if (aliasing.mayAlias(ie.getArg(i), ap.getPlainValue())) {
							if (res == null) res = new HashSet<AccessPath>();							
							
							// Get the parameter locals if we don't have them yet
							if (paramLocals == null)
								paramLocals = callee.getActiveBody().getParameterLocals().toArray(
										new Local[callee.getParameterCount()]);
							
							res.add(ap.copyWithNewValue(paramLocals[i]));
						}
					}
				}
				return res;
			}
		};
	}

	@Override
	public boolean autoAddZero() {
		return false;
	}
	
	/**
	 * Adds a new result of the data flow analysis to the collection
	 * @param resultAbs The abstraction at the sink instruction
	 */
	private void addResult(AbstractionAtSink resultAbs) {
		// Check whether we need to filter a result in a system package
		if (manager.getConfig().getIgnoreFlowsInSystemPackages() && SystemClassHandler.isClassInSystemPackage
				(interproceduralCFG().getMethodOf(resultAbs.getSinkStmt()).getDeclaringClass().getName()))
			return;
		
		// Make sure that the sink statement also appears inside the
		// abstraction
		resultAbs = new AbstractionAtSink
				(resultAbs.getAbstraction().deriveNewAbstraction
						(resultAbs.getAbstraction().getAccessPath(), resultAbs.getSinkStmt()),
				resultAbs.getSinkStmt());
		resultAbs.getAbstraction().setCorrespondingCallSite(resultAbs.getSinkStmt());
		
		Abstraction newAbs = this.results.putIfAbsentElseGet
				(resultAbs, resultAbs.getAbstraction());
		if (newAbs != resultAbs.getAbstraction())
			newAbs.addNeighbor(resultAbs.getAbstraction());
	}

	/**
	 * Gets the results of the data flow analysis
	 */
    public Set<AbstractionAtSink> getResults(){
   		return this.results.keySet();
	}
    
}
