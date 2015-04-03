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
package soot.jimple.infoflow.source;

import heros.InterproceduralCFG;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AnyNewExpr;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.DefinitionStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.data.AccessPath;

/**
 * A {@link ISourceSinkManager} working on lists of source and sink methods
 * 
 * @author Steven Arzt
 */
public class DefaultSourceSinkManager extends MethodBasedSourceSinkManager {

	private Collection<String> sources;
	private Collection<String> sinks;

	private Collection<String> returnTaintMethods;
	private Collection<String> parameterTaintMethods;

	private static final SourceInfo sourceInfo = new SourceInfo(true);

	/**
	 * Creates a new instance of the {@link DefaultSourceSinkManager} class
	 * 
	 * @param sources
	 *            The list of methods to be treated as sources
	 * @param sinks
	 *            The list of methods to be treated as sins
	 */
	public DefaultSourceSinkManager(Collection<String> sources, Collection<String> sinks) {
		this(sources, sinks, null, null);
	}

	/**
	 * Creates a new instance of the {@link DefaultSourceSinkManager} class
	 * 
	 * @param sources
	 *            The list of methods to be treated as sources
	 * @param sinks
	 *            The list of methods to be treated as sinks
	 * @param parameterTaintMethods
	 *            The list of methods whose parameters shall be regarded as
	 *            sources
	 * @param returnTaintMethods
	 *            The list of methods whose return values shall be regarded as
	 *            sinks
	 */
	public DefaultSourceSinkManager(Collection<String> sources, Collection<String> sinks, Collection<String> parameterTaintMethods, Collection<String> returnTaintMethods) {
		this.sources = sources;
		this.sinks = sinks;
		this.parameterTaintMethods = (parameterTaintMethods != null) ? parameterTaintMethods : new HashSet<String>();
		this.returnTaintMethods = (returnTaintMethods != null) ? returnTaintMethods : new HashSet<String>();
	}

	/**
	 * Sets the list of methods to be treated as sources
	 * 
	 * @param sources
	 *            The list of methods to be treated as sources
	 */
	public void setSources(List<String> sources) {
		this.sources = sources;
	}

	/**
	 * Sets the list of methods to be treated as sinks
	 * 
	 * @param sinks
	 *            The list of methods to be treated as sinks
	 */
	public void setSinks(List<String> sinks) {
		this.sinks = sinks;
	}

	@Override
	public SourceInfo getSourceMethodInfo(SootMethod sMethod) {
		if (!sources.contains(sMethod.toString()))
			return null;
		return sourceInfo;
	}

	@Override
	public boolean isSinkMethod(SootMethod sMethod) {
		return sinks.contains(sMethod.toString());
	}

	@Override
	public SourceInfo getSourceInfo(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg) {
		// check wether this is asked from a call to return flow function or
		// from a call flow function:
		SootMethod method = null;
		boolean isCallFlowFunction = false;
		if (sCallSite.containsInvokeExpr()) {
			method = sCallSite.getInvokeExpr().getMethod();
		} else {
			method = cfg.getMethodOf(sCallSite);
			isCallFlowFunction = true;
		}
		// check if this is a source
		if (!sources.contains(method.toString()) && !parameterTaintMethods.contains(method.toString()) && !returnTaintMethods.contains(method.toString())) {
			return null;
		}

		AccessPath ap = null;
		AccessPath[] retAP = null, baseAP = null;
		AccessPath[][] paramAPs = null;

		// if this method has a used return value, taint it
		if ((!isCallFlowFunction && method.getReturnType() != null && sCallSite instanceof DefinitionStmt)) {
			retAP = new AccessPath[1];
			Value leftOp = ((DefinitionStmt) sCallSite).getLeftOp();
			ap = new AccessPath(leftOp, true);
			retAP[0] = ap;
			// else if this is not a static method taint its base object
		} else if (!isCallFlowFunction && sCallSite.getInvokeExpr() instanceof InstanceInvokeExpr) {
			baseAP = new AccessPath[1];
			Value base = ((InstanceInvokeExpr) sCallSite.getInvokeExpr()).getBase();
			ap = new AccessPath(base, true);
			baseAP[0] = ap;
		}
		// if we have to taint parameters do this now
		if (parameterTaintMethods.contains(method.toString())) {
			paramAPs = new AccessPath[method.getParameterCount()][1];
			for (int i = 0; i < paramAPs.length; i++) {
				Value v = (isCallFlowFunction) ? method.getActiveBody().getParameterLocal(i) : ((InvokeExpr) sCallSite).getArg(i);
				paramAPs[i][0] = new AccessPath(v, true);
			}
		}
		AccessPathBundle bundle = new AccessPathBundle(baseAP, null, paramAPs, null, retAP);
		return new SourceInfo(sourceInfo.getTaintSubFields(), sourceInfo.getUserData(), bundle);
	}

	@Override
	public boolean isSink(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg) {
		if (super.isSink(sCallSite, cfg))
			return true;

		if (sCallSite instanceof ReturnStmt)
			if (this.returnTaintMethods != null && this.returnTaintMethods.contains(cfg.getMethodOf(sCallSite).getSignature()))
				return true;

		return false;
	}

	/**
	 * Sets the list of methods whose parameters shall be regarded as taint
	 * sources
	 * 
	 * @param parameterTaintMethods
	 *            The list of methods whose parameters shall be regarded as
	 *            taint sources
	 */
	public void setParameterTaintMethods(List<String> parameterTaintMethods) {
		this.parameterTaintMethods = this.parameterTaintMethods;
	}

	/**
	 * Sets the list of methods whose return values shall be regarded as taint
	 * sinks
	 * 
	 * @param returnTaintMethods
	 *            The list of methods whose return values shall be regarded as
	 *            taint sinks
	 */
	public void setReturnTaintMethods(List<String> returnTaintMethods) {
		this.returnTaintMethods = returnTaintMethods;
	}

	@Override
	public boolean leaks(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg, int index, AccessPath ap) {
		return isSink(sCallSite, cfg);
	}

}
