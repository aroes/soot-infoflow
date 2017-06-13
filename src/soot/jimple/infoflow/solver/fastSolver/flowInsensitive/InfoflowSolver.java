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
package soot.jimple.infoflow.solver.fastSolver.flowInsensitive;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import heros.FlowFunction;
import heros.solver.Pair;
import heros.solver.PathEdge;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.collect.MyConcurrentHashMap;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.problems.AbstractInfoflowProblem;
import soot.jimple.infoflow.solver.IFollowReturnsPastSeedsHandler;
import soot.jimple.infoflow.solver.IInfoflowSolver;
import soot.jimple.infoflow.solver.executors.InterruptableExecutor;
import soot.jimple.infoflow.solver.functions.SolverCallFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverCallToReturnFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverNormalFlowFunction;
import soot.jimple.infoflow.solver.functions.SolverReturnFlowFunction;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
/**
 * We are subclassing the JimpleIFDSSolver because we need the same executor for both the forward and the backward analysis
 * Also we need to be able to insert edges containing new taint information
 * 
 */
public class InfoflowSolver extends FlowInsensitiveSolver<Unit, Abstraction, BiDiInterproceduralCFG<Unit, SootMethod>>
		implements IInfoflowSolver {
	
	private IFollowReturnsPastSeedsHandler followReturnsPastSeedsHandler = null;
	private final AbstractInfoflowProblem problem;
	
	public InfoflowSolver(AbstractInfoflowProblem problem, InterruptableExecutor executor) {
		super(problem);
		this.problem = problem;
		this.executor = executor;
		problem.setSolver(this);		
	}
	
	@Override
	protected InterruptableExecutor getExecutor() {
		return executor;
	}

	@Override
	public boolean processEdge(PathEdge<Unit, Abstraction> edge){
		propagate(edge.factAtSource(), icfg.getMethodOf(edge.getTarget()), edge.factAtTarget(), null, false);
		return true;
	}
	
	@Override
	public void injectContext(IInfoflowSolver otherSolver, SootMethod callee,
			Abstraction d3, Unit callSite, Abstraction d2, Abstraction d1) {
		if (!addIncoming(callee, d3, callSite, d1, d2))
			return;
		
		Set<Pair<Unit, Abstraction>> endSumm = endSummary(callee, d3);		
		if (endSumm != null) {
			Collection<Unit> returnSiteNs = icfg.getReturnSitesOfCallAt(callSite);
			for(Pair<Unit, Abstraction> entry: endSumm) {
				Unit eP = entry.getO1();
				Abstraction d4 = entry.getO2();
				//for each return site
				for(Unit retSiteN: returnSiteNs) {
					SootMethod retMeth = icfg.getMethodOf(retSiteN);							
					//compute return-flow function
					FlowFunction<Abstraction> retFunction = flowFunctions.getReturnFlowFunction(callSite, callee, eP, retSiteN);
					//for each target value of the function
					for(Abstraction d5: computeReturnFlowFunction(retFunction, d3, d4, callSite, Collections.singleton(d1))) {
						if (memoryManager != null)
							d5 = memoryManager.handleGeneratedMemoryObject(d4, d5);
						
						// If we have not changed anything in the callee, we do not need the facts
						// from there. Even if we change something: If we don't need the concrete
						// path, we can skip the callee in the predecessor chain
						Abstraction d5p = d5;
						if (d5.equals(d2))
							d5p = d2;
						else if (setJumpPredecessors && d5p != d2) {
							d5p = d5p.clone();
							d5p.setPredecessor(d2);
						}
						propagate(d1, retMeth, d5p, callSite, false, true);
					}
				}
			}
		}
	}
	
	@Override
	protected Set<Abstraction> computeReturnFlowFunction(
			FlowFunction<Abstraction> retFunction,
			Abstraction d1,
			Abstraction d2,
			Unit callSite,
			Collection<Abstraction> callerSideDs) {
		if (retFunction instanceof SolverReturnFlowFunction) {
			// Get the d1s at the start points of the caller
			return ((SolverReturnFlowFunction) retFunction).computeTargets(d2, d1, callerSideDs);
		}
		else
			return retFunction.computeTargets(d2);
	}

	@Override
	protected Set<Abstraction> computeNormalFlowFunction
			(FlowFunction<Abstraction> flowFunction, Abstraction d1, Abstraction d2) {
		if (flowFunction instanceof SolverNormalFlowFunction)
			return ((SolverNormalFlowFunction) flowFunction).computeTargets(d1, d2);
		else
			return flowFunction.computeTargets(d2);
	}

	@Override
	protected Set<Abstraction> computeCallToReturnFlowFunction
			(FlowFunction<Abstraction> flowFunction, Abstraction d1, Abstraction d2) {
		if (flowFunction instanceof SolverCallToReturnFlowFunction)
			return ((SolverCallToReturnFlowFunction) flowFunction).computeTargets(d1, d2);
		else
			return flowFunction.computeTargets(d2);		
	}

	@Override
	protected Set<Abstraction> computeCallFlowFunction
			(FlowFunction<Abstraction> flowFunction, Abstraction d1, Abstraction d2) {
		if (flowFunction instanceof SolverCallFlowFunction)
			return ((SolverCallFlowFunction) flowFunction).computeTargets(d1, d2);
		else
			return flowFunction.computeTargets(d2);		
	}
	
	@Override
	public void cleanup() {
		this.jumpFunctions = new MyConcurrentHashMap<PathEdge<SootMethod, Abstraction>, Abstraction>();
		this.incoming.clear();
		this.endSummary.clear();
	}
	
	@Override
	public Set<Pair<Unit, Abstraction>> endSummary(SootMethod m, Abstraction d3) {
		return super.endSummary(m, d3);
	}
	
	@Override
	protected void processExit(Abstraction d1, Unit n, Abstraction d2) {
		super.processExit(d1, n, d2);
		
		if (followReturnsPastSeeds && followReturnsPastSeedsHandler != null) {
			final SootMethod methodThatNeedsSummary = icfg.getMethodOf(n);
			final Map<Unit, Map<Abstraction, Abstraction>> inc = incoming(d1, methodThatNeedsSummary);
			
			if (inc == null || inc.isEmpty())
				followReturnsPastSeedsHandler.handleFollowReturnsPastSeeds(d1, n, d2);
		}
	}
	
	@Override
	public void setFollowReturnsPastSeedsHandler(IFollowReturnsPastSeedsHandler handler) {
		this.followReturnsPastSeedsHandler = handler;
	}

	@Override
	public long getPropagationCount() {
		return propagationCount;
	}

	@Override
	public void setSolverId(boolean solverId) {
		super.setSolverId(solverId);
	}

	@Override
	public AbstractInfoflowProblem getTabulationProblem() {
		return this.problem;
	}
	
}
