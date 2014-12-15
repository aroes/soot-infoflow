package soot.jimple.infoflow.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.IdentityStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Jimple;
import soot.jimple.ParameterRef;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.ThisRef;
import soot.jimple.infoflow.solver.IInfoflowCFG;
import soot.jimple.infoflow.source.ISourceSinkManager;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;
import soot.util.queue.QueueReader;

public class InterproceduralConstantValuePropagator extends SceneTransformer {
	
	private final IInfoflowCFG icfg;
	private final Set<SootMethod> excludedMethods;
	private final ISourceSinkManager sourceSinkManager;
	private final ITaintPropagationWrapper taintWrapper;
	
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
	
	@Override
	protected void internalTransform(String phaseName, Map<String, String> options) {
		// Collect all application methods that take parameters or return values
		for (QueueReader<MethodOrMethodContext> rdr = Scene.v().getReachableMethods().listener();
				rdr.hasNext(); ) {
			MethodOrMethodContext mom = rdr.next();
			SootMethod sm = mom.method();

			if (sm == null || !sm.hasActiveBody())
				continue;
			if (SystemClassHandler.isClassInSystemPackage(sm.getDeclaringClass().getName()))
				continue;
			
			// If this callee is excluded, we do not propagate out of it
			if (excludedMethods != null && excludedMethods.contains(sm))
				return;
			
			// Make sure that we get constants as often as possible
			ConstantPropagatorAndFolder.v().transform(sm.getActiveBody());
			
			if (sm.getReturnType() != VoidType.v() || sm.getParameterCount() > 0) {
				if (sm.getParameterCount() > 0)
					propagateConstantsIntoCallee(sm);
				
				if (typeSupportsConstants(sm.getReturnType()))
					propagateReturnValueIntoCallers(sm);
			}
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
						
					// If the call has no side effects, we can remove it altogether,
					// otherwise we can just propagate the return value
					Unit assignConst = Jimple.v().newAssignStmt(assign.getLeftOp(), value);
					if (!icfg.hasSideEffects(sm)) {
						caller.getActiveBody().getUnits().swapWith(assign, assignConst);
						ConstantPropagatorAndFolder.v().transform(caller.getActiveBody());
					}
					else {
						caller.getActiveBody().getUnits().insertAfter(assignConst, assign);
						ConstantPropagatorAndFolder.v().transform(caller.getActiveBody());
						caller.getActiveBody().getUnits().remove(assignConst);
					}
				}
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
