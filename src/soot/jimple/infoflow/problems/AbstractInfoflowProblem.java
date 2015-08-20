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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.ArrayType;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.infoflow.collect.MyConcurrentHashMap;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.handlers.TaintPropagationHandler;
import soot.jimple.infoflow.nativ.INativeCallHandler;
import soot.jimple.infoflow.solver.IInfoflowSolver;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.toolkits.ide.DefaultJimpleIFDSTabulationProblem;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;

/**
 * abstract super class which 
 * 	- concentrates functionality used by InfoflowProblem and BackwardsInfoflowProblem
 *  - contains helper functions which should not pollute the naturally large InfofflowProblems
 *
 */
public abstract class AbstractInfoflowProblem extends DefaultJimpleIFDSTabulationProblem<Abstraction,
			BiDiInterproceduralCFG<Unit, SootMethod>> {
	
	protected final InfoflowManager manager;
	
	protected final Map<Unit, Set<Abstraction>> initialSeeds = new HashMap<Unit, Set<Abstraction>>();
	protected ITaintPropagationWrapper taintWrapper;	
	protected INativeCallHandler ncHandler;
	
    protected final Logger logger = LoggerFactory.getLogger(getClass());

	private Abstraction zeroValue = null;
	
	protected IInfoflowSolver solver = null;
	
	protected Set<TaintPropagationHandler> taintPropagationHandlers = null;

	private MyConcurrentHashMap<Unit, Set<Unit>> activationUnitsToCallSites =
			new MyConcurrentHashMap<Unit, Set<Unit>>();
	
	public AbstractInfoflowProblem(InfoflowManager manager) {
		super(manager.getICFG());
		this.manager = manager;
	}
	
	public void setSolver(IInfoflowSolver solver) {
		this.solver = solver;
	}
	
	public void setZeroValue(Abstraction zeroValue) {
		this.zeroValue = zeroValue;
	}

	/**
	 * we need this option as we start directly at the sources, but need to go 
	 * backward in the call stack
	 */
	@Override
	public boolean followReturnsPastSeeds(){
		return true;
	}
	
	/**
	 * Sets the taint wrapper that shall be used for applying external library
	 * models
	 * @param wrapper The taint wrapper that shall be used for applying external
	 * library models
	 */
	public void setTaintWrapper(ITaintPropagationWrapper wrapper){
		this.taintWrapper = wrapper;
	}
	
	/**
	 * Sets the handler class to be used for modeling the effects of native
	 * methods on the taint state
	 * @param handler The native call handler to use
	 */
	public void setNativeCallHandler(INativeCallHandler handler) {
		this.ncHandler = handler;
	}
	
	/**
	 * Gets whether the given method is an entry point, i.e. one of the initial
	 * seeds belongs to the given method
	 * @param sm The method to check
	 * @return True if the given method is an entry point, otherwise false
	 */
	protected boolean isInitialMethod(SootMethod sm) {
		for (Unit u : this.initialSeeds.keySet())
			if (interproceduralCFG().getMethodOf(u) == sm)
				return true;
		return false;
	}
	
	@Override
	public Map<Unit, Set<Abstraction>> initialSeeds() {
		return initialSeeds;
	}
	
	/**
	 * performance improvement: since we start directly at the sources, we do not 
	 * need to generate additional taints unconditionally
	 */
	@Override
	public boolean autoAddZero() {
		return false;
	}
	
	protected boolean isCallSiteActivatingTaint(Unit callSite, Unit activationUnit) {
		if (!manager.getConfig().getFlowSensitiveAliasing())
			return false;

		if (activationUnit == null)
			return false;
		Set<Unit> callSites = activationUnitsToCallSites.get(activationUnit);
		return (callSites != null && callSites.contains(callSite));
	}
	
	protected boolean registerActivationCallSite(Unit callSite, SootMethod callee, Abstraction activationAbs) {
		if (!manager.getConfig().getFlowSensitiveAliasing())
			return false;
		Unit activationUnit = activationAbs.getActivationUnit();
		if (activationUnit == null)
			return false;

		Set<Unit> callSites = activationUnitsToCallSites.putIfAbsentElseGet
				(activationUnit, new ConcurrentHashSet<Unit>());
		if (callSites.contains(callSite))
			return false;
		
		if (!activationAbs.isAbstractionActive())
			if (!callee.getActiveBody().getUnits().contains(activationUnit)) {
				boolean found = false;
				for (Unit au : callSites)
					if (callee.getActiveBody().getUnits().contains(au)) {
						found = true;
						break;
					}
				if (!found)
					return false;
			}

		return callSites.add(callSite);
	}
	
	public void setActivationUnitsToCallSites(AbstractInfoflowProblem other) {
		this.activationUnitsToCallSites = other.activationUnitsToCallSites;
	}

	@Override
	public IInfoflowCFG interproceduralCFG() {
		return (IInfoflowCFG) super.interproceduralCFG();
	}
	
	/**
	 * Adds the given initial seeds to the information flow problem
	 * @param unit The unit to be considered as a seed
	 * @param seeds The abstractions with which to start at the given seed
	 */
	public void addInitialSeeds(Unit unit, Set<Abstraction> seeds) {
		if (this.initialSeeds.containsKey(unit))
			this.initialSeeds.get(unit).addAll(seeds);
		else
			this.initialSeeds.put(unit, new HashSet<Abstraction>(seeds));
	}
	
	/**
	 * Gets whether this information flow problem has initial seeds
	 * @return True if this information flow problem has initial seeds,
	 * otherwise false
	 */
	public boolean hasInitialSeeds() {
		return !this.initialSeeds.isEmpty();
	}

	/**
	 * Gets the initial seeds with which this information flow problem has been
	 * configured
	 * @return The initial seeds with which this information flow problem has
	 * been configured.
	 */
	public Map<Unit, Set<Abstraction>> getInitialSeeds() {
		return this.initialSeeds;
	}
	
	/**
	 * Adds a handler which is invoked whenever a taint is propagated
	 * @param handler The handler to be invoked when propagating taints
	 */
	public void addTaintPropagationHandler(TaintPropagationHandler handler) {
		if (this.taintPropagationHandlers == null)
			this.taintPropagationHandlers = new HashSet<>();
		this.taintPropagationHandlers.add(handler);
	}
	
	/**
	 * Builds a new array of the given type if it is a base type or increments
	 * the dimensions of the given array by 1 otherwise.
	 * @param type The base type or incoming array
	 * @return The resulting array
	 */
	public Type buildArrayOrAddDimension(Type type) {
		if (type instanceof ArrayType) {
			ArrayType array = (ArrayType) type;
			return array.makeArrayType();
		}
		else
			return ArrayType.v(type, 1);
	}
		
	@Override
	public Abstraction createZeroValue() {
		if (zeroValue == null)
			zeroValue = Abstraction.getZeroAbstraction(
					manager.getConfig().getFlowSensitiveAliasing());
		return zeroValue;
	}
	
	protected Abstraction getZeroValue() {
		return zeroValue;
	}
	
	/**
	 * Checks whether the given call is a call to Executor.execute() or
	 * AccessController.doPrivileged() and whether the callee matches
	 * the expected method signature
	 * @param ie The invocation expression to check
	 * @param dest The callee of the given invocation expression
	 * @return True if the given invocation expression and callee are a valid
	 * call to Executor.execute() or AccessController.doPrivileged()
	 */
	protected boolean isExecutorExecute(InvokeExpr ie, SootMethod dest) {
		if (ie == null || dest == null)
			return false;
		
		SootMethod ieMethod = ie.getMethod();
		if (!ieMethod.getName().equals("execute") && !ieMethod.getName().equals("doPrivileged"))
			return false;
		
		final String ieSubSig = ieMethod.getSubSignature();
		final String calleeSubSig = dest.getSubSignature();
		
		if (ieSubSig.equals("void execute(java.lang.Runnable)")
				&& calleeSubSig.equals("void run()"))
			return true;
		
		if (calleeSubSig.equals("java.lang.Object run()")) {
			if (ieSubSig.equals("java.lang.Object doPrivileged(java.security.PrivilegedAction)"))
				return true;
			if (ieSubSig.equals("java.lang.Object doPrivileged(java.security.PrivilegedAction,"
					+ "java.security.AccessControlContext)"))
				return true;
			if (ieSubSig.equals("java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction)"))
				return true;
			if (ieSubSig.equals("java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction,"
					+ "java.security.AccessControlContext)"))
				return true;
		}
		return false;
	}
	
}
