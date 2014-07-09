package soot.jimple.infoflow.data.pathBuilders;

import soot.jimple.infoflow.solver.IInfoflowCFG;

/**
 * Abstract base class for all abstraction path builders
 * 
 * @author Steven Arzt
 */
public abstract class AbstractAbstractionPathBuilder implements
		IAbstractionPathBuilder {

	protected final IInfoflowCFG icfg;
	
	public AbstractAbstractionPathBuilder(IInfoflowCFG icfg) {
		this.icfg = icfg;
	}

}
