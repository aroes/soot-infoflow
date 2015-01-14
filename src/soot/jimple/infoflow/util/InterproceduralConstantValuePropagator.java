package soot.jimple.infoflow.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.DoubleType;
import soot.FloatType;
import soot.IntType;
import soot.Local;
import soot.LongType;
import soot.MethodOrMethodContext;
import soot.RefType;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.VoidType;
import soot.JastAddJ.DivExpr;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.IdentityStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.NewExpr;
import soot.jimple.ParameterRef;
import soot.jimple.RemExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.ThisRef;
import soot.jimple.ThrowStmt;
import soot.jimple.infoflow.solver.IInfoflowCFG;
import soot.jimple.infoflow.source.ISourceSinkManager;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;
import soot.options.Options;
import soot.util.queue.QueueReader;


public class InterproceduralConstantValuePropagator extends SceneTransformer {
	
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final IInfoflowCFG icfg;
	private final Set<SootMethod> excludedMethods;
	private final ISourceSinkManager sourceSinkManager;
	private final ITaintPropagationWrapper taintWrapper;
	private boolean removeSideEffectFreeMethods = true;
	
	protected final Map<SootMethod, Boolean> methodSideEffects =
			new ConcurrentHashMap<SootMethod, Boolean>();
	
	/**
	 * Creates a new instance of the {@link InterproceduralConstantValuePropagator}
	 * class
	 * @param icfg The interprocedural control flow graph to use
	 */
	public InterproceduralConstantValuePropagator(IInfoflowCFG icfg) {
		this.icfg = icfg;
		this.excludedMethods = null;
		this.sourceSinkManager = null;
		this.taintWrapper = null;
	}
	
	/**
	 * Creates a new instance of the {@link InterproceduralConstantValuePropagator}
	 * class
	 * @param icfg The interprocedural control flow graph to use
	 * @param excludedMethods The methods that shall be excluded. If one of these
	 * methods calls another method with a constant argument, this argument will
	 * not be propagated into the callee.
	 * @param sourceSinkManager The SourceSinkManager to be used for not
	 * propagating constants out of source methods
	 * @param taintWrapper The taint wrapper to be used for not breaking dummy
	 * values that will later be replaced by artificial taints
	 */
	public InterproceduralConstantValuePropagator(IInfoflowCFG icfg,
			Collection<SootMethod> excludedMethods,
			ISourceSinkManager sourceSinkManager,
			ITaintPropagationWrapper taintWrapper) {
		this.icfg = icfg;
		this.excludedMethods = new HashSet<SootMethod>(excludedMethods);
		this.sourceSinkManager = sourceSinkManager;
		this.taintWrapper = taintWrapper;
	}
	
	/**
	 * Sets whether side-effect free methods that do not call sinks shall be
	 * removed
	 * @param removeSideEffectFreeMethods The if side-effect free methods that
	 * do not call sinks shall be removed, otherwise false
	 */
	public void setRemoveSideEffectFreeMethods(boolean removeSideEffectFreeMethods) {
		this.removeSideEffectFreeMethods = removeSideEffectFreeMethods;
	}
	
	@Override
	protected void internalTransform(String phaseName, Map<String, String> options) {
		logger.info("Removing side-effect free methods is "
				+ (removeSideEffectFreeMethods ? "enabled" : "disabled"));
		
		// Collect all application methods that take parameters or return values
		for (QueueReader<MethodOrMethodContext> rdr = Scene.v().getReachableMethods().listener();
				rdr.hasNext(); ) {
			MethodOrMethodContext mom = rdr.next();
			SootMethod sm = mom.method();
			if (sm == null || !sm.hasActiveBody())
				continue;
			
			// If this callee is excluded, we do not propagate out of it
			if (excludedMethods != null && excludedMethods.contains(sm))
				continue;
			if (SystemClassHandler.isClassInSystemPackage(sm.getDeclaringClass().getName()))
				continue;
			
			// If this method returns nothing, is side-effect free and does not
			// call a sink, we can remove it altogether.
			if (removeSideEffectFreeMethods
					&& sm.getReturnType() == VoidType.v()
					&& !hasSideEffectsOrCallsSink(sm)
					&& !isSinkOrTaintWrapped(sm)) {
				removeAllCallers(sm);
				continue;
			}
			
			if (sm.getReturnType() != VoidType.v() || sm.getParameterCount() > 0) {
				if (sm.getParameterCount() > 0)
					propagateConstantsIntoCallee(sm);
				
				if (typeSupportsConstants(sm.getReturnType()))
					propagateReturnValueIntoCallers(sm);
			}
		}
	}
	
	/**
	 * Checks whether the given method is a sink or is accepted by the taint
	 * wrapper
	 * @param method The method to check
	 * @return True if the given method is a sink or is accepted by the taint
	 * wrapper, otherwise false
	 */
	private boolean isSinkOrTaintWrapped(SootMethod method) {
		// If this method is a sink on its own, we must keep it
		for (Unit callSite : icfg.getCallersOf(method))
			if (sourceSinkManager.isSink((Stmt) callSite, icfg)) {
				methodSideEffects.put(method, true);
				return true;
			}
		
		// If this method is wrapped, we need to keep it
		if (taintWrapper != null && taintWrapper.supportsCallee(method)) {
			methodSideEffects.put(method, true);
			return true;
		}
		
		return false;
	}

	/**
	 * Removes all statements calling the given method
	 * @param sm The method that shall no longer be called
	 */
	private void removeAllCallers(SootMethod sm) {
		for (Unit callSite : icfg.getCallersOf(sm)) {
			// Make sure that we don't access anything we have already removed
			SootMethod caller = icfg.getMethodOf(callSite);
			if (!caller.getActiveBody().getUnits().contains(callSite))
				continue;
			
			// Remove the call
			caller.getActiveBody().getUnits().remove(callSite);

			// Fix the callgraph
			if (Scene.v().hasCallGraph())
				Scene.v().getCallGraph().removeAllEdgesOutOf(callSite);
		}
	}

	/**
	 * Checks whether constant handling is supported for the given type
	 * @param returnType The type to check
	 * @return True if a value of the given type can be represented as a
	 * constant, otherwise false
	 */
	private boolean typeSupportsConstants(Type returnType) {
		if (returnType == IntType.v()
				|| returnType == LongType.v()
				|| returnType == FloatType.v()
				|| returnType == DoubleType.v())
			return true;
		
		if (returnType instanceof RefType)
			if (((RefType) returnType).getClassName().equals("java.lang.String"))
				return true;
		
		return false;
	}
	
	/**
	 * Propagates the return value of the given method into all of its callers
	 * if the value is constant
	 * @param sm The method whose value to propagate
	 */
	private void propagateReturnValueIntoCallers(SootMethod sm) {		
		// If we have a taint wrapper, we need keep the stub untouched since we
		// don't the artificial taint the wrapper will come up with
		if (taintWrapper != null && taintWrapper.supportsCallee(sm))
			return;

		// We need to make sure that all exit nodes agree on the same
		// constant value
		Constant value = null;
		for (Unit retSite : icfg.getEndPointsOf(sm)) {
			// Skip exceptional exits
			if (!(retSite instanceof ReturnStmt))
				continue;
			
			ReturnStmt retStmt = (ReturnStmt) retSite;
			if (!(retStmt.getOp() instanceof Constant))
				return;
			
			if (value != null && retStmt.getOp() != value)
				return;
			value = (Constant) retStmt.getOp();
		}
		
		// Propagate the return value into the callers
		if (value != null)
			for (Unit callSite : icfg.getCallersOf(sm))
				if (callSite instanceof AssignStmt) {
					AssignStmt assign = (AssignStmt) callSite;
					
					// If this is a call to a source method, we do not propagate
					// constants out of the callee for not destroying data flows
					if (sourceSinkManager != null
							&& sourceSinkManager.getSourceInfo(assign, icfg) != null)
						continue;
					
					// Make sure that we don't access anything we have already removed
					SootMethod caller = icfg.getMethodOf(assign);
					if (!caller.getActiveBody().getUnits().contains(assign))
						continue;
					
					// If the call site has multiple callees, we cannot propagate a
					// single constant
					if (icfg.getCalleesOfCallAt(callSite).size() > 1)
						continue;
					
					// If the call has no side effects, we can remove it altogether,
					// otherwise we can just propagate the return value
					Unit assignConst = Jimple.v().newAssignStmt(assign.getLeftOp(), value);
					if (!hasSideEffectsOrCallsSink(sm)) {
						// We don't have side effects, so we can just change
						// a = b.foo() into a = 0.
						caller.getActiveBody().getUnits().swapWith(assign, assignConst);
						if (!excludedMethods.contains(caller))
							ConstantPropagatorAndFolder.v().transform(caller.getActiveBody());
						
						// Fix the callgraph
						if (Scene.v().hasCallGraph())
							Scene.v().getCallGraph().removeAllEdgesOutOf(assign);
					}
					else {
						// We have side effects, so we need to keep the method call. Change
						// a = b.foo() into b.foo(); a = 0;
						caller.getActiveBody().getUnits().insertAfter(assignConst, assign);
						if (!excludedMethods.contains(caller))
							ConstantPropagatorAndFolder.v().transform(caller.getActiveBody());
						caller.getActiveBody().getUnits().remove(assignConst);
						
						Stmt inv = Jimple.v().newInvokeStmt(assign.getInvokeExpr());
						caller.getActiveBody().getUnits().swapWith(assign, inv);
						
						// Fix the callgraph
						if (Scene.v().hasCallGraph())
							Scene.v().getCallGraph().swapEdgesOutOf(assign, inv);
					}
				}
	}
	
	/**
	 * Checks whether the given method or one of its transitive callees has
	 * side-effects or calls a sink method
	 * @param method The method to check
	 * @return True if the given method or one of its transitive callees has
	 * side-effects or calls a sink method, otherwise false.
	 */
	private boolean hasSideEffectsOrCallsSink(SootMethod method) {
		return hasSideEffectsOrCallsSink(method, new HashSet<SootMethod>());
	}
	
	/**
	 * Checks whether the given method or one of its transitive callees has
	 * side-effects or calls a sink method
	 * @param method The method to check
	 * @param runList A set to receive all methods that have already been
	 * processed
	 * @param cache The cache in which to store the results
	 * @return True if the given method or one of its transitive callees has
	 * side-effects or calls a sink method, otherwise false.
	 */
	private boolean hasSideEffectsOrCallsSink(SootMethod method,
			Set<SootMethod> runList) {		
		// Without a body, we cannot say much
		if (!method.hasActiveBody())
			return false;
		
		// Do we already have an entry?
		Boolean hasSideEffects = methodSideEffects.get(method);
		if (hasSideEffects != null)
			return hasSideEffects;
		
		// Do not process the same method twice
		if (!runList.add(method))
			return false;
		
		// If this is an Android stub method that just throws a stub exception,
		// this will never happen in practice and can be removed
		if (methodIsAndroidStub(method)) {
			methodSideEffects.put(method, false);
			return false;
		}
				
		// Scan for references to this variable
		for (Unit u : method.getActiveBody().getUnits()) {
			if (u instanceof ThrowStmt) {
				methodSideEffects.put(method, true);
				return true;
			}
			else if (u instanceof AssignStmt) {
				AssignStmt assign = (AssignStmt) u;
				if (assign.getLeftOp() instanceof FieldRef
						|| assign.getLeftOp() instanceof ArrayRef
						|| assign.getRightOp() instanceof FieldRef
						|| assign.getRightOp() instanceof ArrayRef
						|| assign.getRightOp() instanceof DivExpr
						|| assign.getRightOp() instanceof RemExpr) {
					methodSideEffects.put(method, true);
					return true;
				}
			}
			
			Stmt s = (Stmt) u;
			
			// If this method calls another method for which we have a taint
			// wrapper, we need to conservatively assume that the taint wrapper
			// can do anything
			if (taintWrapper != null && taintWrapper.supportsCallee(s, icfg)) {
				methodSideEffects.put(method, true);
				return true;
			}
			
			if (s.containsInvokeExpr()) {
				// If this method calls a sink, we need to keep it
				if (sourceSinkManager.isSink((Stmt) u, icfg)) {
					methodSideEffects.put(method, true);
					return true;
				}
				
				// Check the callees
				for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().edgesOutOf(u); edgeIt.hasNext(); ) {
					Edge e = edgeIt.next();
						if (hasSideEffectsOrCallsSink(e.getTgt().method(), runList))
							return true;
				}
			}
		}
		
		// Variable is not read
		methodSideEffects.put(method, false);
		return false;
	}
	
	/**
	 * Checks whether the given method is a library stub method
	 * @param method The method to check
	 * @return True if the given method is an Android library stub, false
	 * otherwise
	 */
	private boolean methodIsAndroidStub(SootMethod method) {
		if (!(Options.v().src_prec() == Options.src_prec_apk
				&& method.getDeclaringClass().isLibraryClass()
				&& SystemClassHandler.isClassInSystemPackage(
						method.getDeclaringClass().getName())))
			return false;
		
		// Check whether there is only a single throw statement
		for (Unit u : method.getActiveBody().getUnits()) {
			if (u instanceof DefinitionStmt) {
				DefinitionStmt defStmt = (DefinitionStmt) u;
				if (!(defStmt.getRightOp() instanceof ThisRef)
						&& !(defStmt.getRightOp() instanceof ParameterRef)
						&& !(defStmt.getRightOp() instanceof NewExpr))
					return false;
			}
			else if (u instanceof InvokeStmt) {
				InvokeStmt stmt = (InvokeStmt) u;
				
				// Check for exception constructor invocations
				SootMethod callee = stmt.getInvokeExpr().getMethod();
				if (!callee.getSubSignature().equals("void <init>(java.lang.String)"))
					// Check for super class constructor invocation
					if (!(callee.getDeclaringClass().hasSuperclass()
							&& callee.getDeclaringClass() == method.getDeclaringClass().getSuperclass()
							&& callee.getName().equals("<init>")))
						return false;
			}
			else if (!(u instanceof ThrowStmt))
				return false;
		}
		return true;
	}

	/**
	 * Checks whether all call sites for a specific callee agree on the same
	 * constant value for one or more arguments. If so, these constant values
	 * are propagated into the callee.
	 * @param sm The method for which to look for call sites.
	 */
	private void propagateConstantsIntoCallee(SootMethod sm) {		
		Collection<Unit> callSites = icfg.getCallersOf(sm);
		if (callSites.isEmpty())
			return;
		
		boolean[] isConstant = new boolean[sm.getParameterCount()];
		Constant[] values = new Constant[sm.getParameterCount()];
		for (int i = 0; i < isConstant.length; i++)
			isConstant[i] = true;
		
		// Do all of our callees agree on one constant value?
		boolean hasCallSites = false;
		for (Unit callSite : callSites) {
			// If this call site is in an excluded method, we ignore it
			if (excludedMethods != null && excludedMethods.contains(icfg.getMethodOf(callSite)))
				continue;
			
			InvokeExpr iiExpr = ((Stmt) callSite).getInvokeExpr();
			hasCallSites = true;
			
			// Check whether we have constant parameter values
			for (int i = 0; i < iiExpr.getArgCount(); i++) {
				final Value argVal = iiExpr.getArg(i);
				if (argVal instanceof Constant) {
					// If we already have a value for this argument and the
					// new one does not agree, this parameter is not globally
					// constant.
					if (values[i] != null && !values[i].equals(argVal))
						isConstant[i] = false;
					else
						values[i] = (Constant) argVal;
				}
				else
					isConstant[i] = false;
			}
		}
		
		if (hasCallSites) {
			// Get the constant parameters
			List<Unit> inserted = null;
			for (int i = 0; i < isConstant.length; i++) {
				if (isConstant[i]) {
					// Propagate the constant into the callee
					Local paramLocal = sm.getActiveBody().getParameterLocal(i);
					Unit point = getFirstNonIdentityStmt(sm);
					Unit assignConst = Jimple.v().newAssignStmt(paramLocal, values[i]);
					sm.getActiveBody().getUnits().insertBefore(assignConst, point);
					
					if (inserted == null)
						inserted = new ArrayList<Unit>();
					inserted.add(assignConst);
				}
			}
			
			// Propagate the constant inside the callee
			if (inserted != null) {
				ConstantPropagatorAndFolder.v().transform(sm.getActiveBody());
				for (Unit u : inserted)
					sm.getActiveBody().getUnits().remove(u);
			}
		}
	}
	
	/**
	 * Gets the first statement in the body of the given method that does not
	 * assign the "this" local or a parameter local
	 * @param sm The method in whose body to look
	 * @return The first non-identity statement in the body of the given method.
	 */
	private Unit getFirstNonIdentityStmt(SootMethod sm) {
		for (Unit u : sm.getActiveBody().getUnits()) {
			if (!(u instanceof IdentityStmt))
				return u;
			
			IdentityStmt id = (IdentityStmt) u;
			if (!(id.getRightOp() instanceof ThisRef)
					&& !(id.getRightOp() instanceof ParameterRef))
				return u;
		}
		return null;
	}
	
}
