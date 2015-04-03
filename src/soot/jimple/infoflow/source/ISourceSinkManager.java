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
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.infoflow.data.AccessPath;
/**
 * the SourceSinkManager can tell if a statement contains a source or a sink
 */
public interface ISourceSinkManager {

	/**
	 * Determines if a method called by the Stmt is a source method or not. If
	 * so, additional information is returned
	 * @param sCallSite a Stmt which should include an invokeExrp calling a method
	 * @param cfg the interprocedural controlflow graph
	 * @return A SourceInfo object containing additional information if this call
	 * is a source, otherwise null
	 */
	public SourceInfo getSourceInfo(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg);
	
	/**
	 * determines if a method called by the Stmt is a sink method or not
	 * @param sCallSite a Stmt which should include an invokeExrp calling a method
	 * @param cfg the interprocedural controlflow graph
	 * @return true if sink method is called
	 */
	public boolean isSink(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg);

	/**
	 * Checks if the given access path at this statement will leak.
	 * @param sCallSite the call site to check
	 * @param cfg the control flow graph of the current problem
	 * @param index If the access path is from the base object of the callee, the index must be negative. 
	 * 				If the given access path is from a parameter, the index is the index of the parameter counted from 0.
	 * @param ap the access path to check
	 * @return true if the access path will leak in this method, false if not or if this method is not a sink
	 * @author Daniel Magin
	 */
	boolean leaks(Stmt sCallSite, InterproceduralCFG<Unit, SootMethod> cfg, int index, AccessPath ap);

}
