package soot.jimple.infoflow;

import soot.jimple.infoflow.solver.IInfoflowSolver;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.source.ISourceSinkManager;

/**
 * Manager class for passing internal data flow objects to interface
 * implementors
 * 
 * @author Steven Arzt
 *
 */
public class InfoflowManager {
	
	private final IInfoflowSolver forwardSolver;
	private final IInfoflowCFG icfg;
	private final ISourceSinkManager sourceSinkManager;
	
	InfoflowManager(IInfoflowSolver forwardSolver, IInfoflowCFG icfg,
			ISourceSinkManager sourceSinkManager) {
		this.forwardSolver = forwardSolver;
		this.icfg = icfg;
		this.sourceSinkManager = sourceSinkManager;
	}
	
	/**
	 * Gets the IFDS solver that propagates edges forward
	 * @return The IFDS solver that propagates edges forward
	 */
	public IInfoflowSolver getForwardSolver() {
		return this.forwardSolver;
	}
	
	/**
	 * Gets the interprocedural control flow graph
	 * @return The interprocedural control flow graph
	 */
	public IInfoflowCFG getICFG() {
		return this.icfg;
	}
	
	/**
	 * Gets the SourceSinkManager implementation
	 * @return The SourceSinkManager implementation
	 */
	public ISourceSinkManager getSourceSinkManager() {
		return this.sourceSinkManager;
	}
	
}
