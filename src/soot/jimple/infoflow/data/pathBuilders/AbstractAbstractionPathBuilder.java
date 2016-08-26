package soot.jimple.infoflow.data.pathBuilders;

import java.util.HashSet;
import java.util.Set;

import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

/**
 * Abstract base class for all abstraction path builders
 * 
 * @author Steven Arzt
 */
public abstract class AbstractAbstractionPathBuilder implements
		IAbstractionPathBuilder {
	
	protected final IInfoflowCFG icfg;
	protected final boolean reconstructPaths;
	protected Set<OnPathBuilderResultAvailable> resultAvailableHandlers = null;
	
	/**
	 * Creates a new instance of the {@link AbstractAbstractionPathBuilder} class
	 * @param icfg The interprocedural control flow graph
	 * @param reconstructPaths True if the exact propagation path between source
	 * and sink shall be reconstructed.
	 */
	public AbstractAbstractionPathBuilder(IInfoflowCFG icfg,
			boolean reconstructPaths) {
		this.icfg = icfg;
		this.reconstructPaths = reconstructPaths;
	}
	
	/**
	 * Reduces the abstraction path by compacting the predecessor chain.
	 * A -> B -> C becomes A -> C if B doesn't add any further information
	 * on sources.
	 * @param obj The abstraction at which to start the reduction
	 */
	protected void reduceAbstractionPath(Abstraction obj) {
		/*
		Abstraction pred = obj.getPredecessor();
		while (obj.getNeighbors() == null
				&& pred != null
				&& pred.getNeighbors() == null
				&& pred.getCorrespondingCallSite() == null
				&& pred.getCurrentStmt() == null) {
			if (pred.getPredecessor() == null) {
				// Do not copy over the source context as this would disable the
				// whole mechanism of abstraction chaining
				break;
			}
			else {
				pred = pred.getPredecessor();
				
				if (pred.toString().contains("tainted"))
					System.out.println("x");
				
				obj.setPredecessor(pred);
			}
		}
		*/
	}

	@Override
	public void addResultAvailableHandler(OnPathBuilderResultAvailable handler) {
		if (this.resultAvailableHandlers == null)
			this.resultAvailableHandlers = new HashSet<>();
		this.resultAvailableHandlers.add(handler);
	}

}
