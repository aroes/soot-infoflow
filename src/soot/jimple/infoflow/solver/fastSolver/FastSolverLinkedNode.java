package soot.jimple.infoflow.solver.fastSolver;

import heros.solver.LinkedNode;

/**
 * Special interface of {@link LinkedNode} that allows the FastSolver to reduce
 * the size of the taint graph
 * 
 * @author Steven Arzt
 */
public interface FastSolverLinkedNode<D, N> extends LinkedNode<D> {

	public void setPredecessor(D predecessor);
	
	public void setCallSite(N callSite);
	
}
