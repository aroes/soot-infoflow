package soot.jimple.infoflow.data.pathBuilders;

import java.util.Set;

import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.results.InfoflowResults;

/**
 * An empty implementation of {@link IAbstractionPathBuilder} that always
 * returns the empty set. For internal use only.
 * 
 * @author Steven Arzt
 */
public class EmptyPathBuilder implements IAbstractionPathBuilder {
	
	@Override
	public void computeTaintPaths(Set<AbstractionAtSink> res) {
	}

	@Override
	public InfoflowResults getResults() {
		return new InfoflowResults();
	}

	@Override
	public void addResultAvailableHandler(OnPathBuilderResultAvailable handler) {
	}

	@Override
	public void runIncrementalPathCompuation() {
	}

	@Override
	public void forceTerminate() {
	}

	@Override
	public boolean isTerminated() {
		return false;
	}

	@Override
	public boolean isKilled() {
		return false;
	}

	@Override
	public void reset() {
	}

	@Override
	public void addStatusListener(IMemoryBoundedSolverStatusNotification listener) {
		// not supported
	}
	
}
