package soot.jimple.infoflow.solver.fastSolver;

import heros.solver.LinkedNode;

/**
 * Special interface of {@link LinkedNode} that allows the FastSolver to reduce
 * the size of the taint graph
 * 
 * @author Steven Arzt
 */
public interface FastSolverLinkedNode<D, N> extends LinkedNode<D>, Cloneable {
	
	/**
	 * Explicitly sets the predecessor of this node.
	 * @param predecessor The predecessor node to set
	 */
	public void setPredecessor(D predecessor);
	
	/**
	 * Gets the predecessor of this node
	 * @return The predecessor of this node is applicable, null for source nodes
	 */
	public D getPredecessor();
	
	/**
	 * Clones this data flow abstraction
	 * @return A clone of the current data flow abstraction
	 */
	public D clone();
	
	/**
	 * If this abstraction supports alias analysis, this returns the active copy
	 * of the current abstraction. Otherwise, "this" is returned.
	 * @return The active copy if supported, otherwise the "this" reference
	 */
	public D getActiveCopy();
	
}
