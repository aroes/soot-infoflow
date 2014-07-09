package soot.jimple.infoflow.data.pathBuilders;

import soot.jimple.infoflow.solver.IInfoflowCFG;

/**
 * Default factory class for abstraction path builders
 * 
 * @author Steven Arzt
 */
public class DefaultPathBuilderFactory implements IPathBuilderFactory {
	
	/**
	 * Enumeration containing the supported path builders
	 */
	public enum PathBuilder {
		Recursive,
		Threaded,
		SemiThreaded
	}
	
	private final PathBuilder pathBuilder;
	
	/**
	 * Creates a new instance of the {@link DefaultPathBuilderFactory} class
	 */
	public DefaultPathBuilderFactory() {
		this(PathBuilder.SemiThreaded);
	}

	/**
	 * Creates a new instance of the {@link DefaultPathBuilderFactory} class
	 * @param builder The path building algorithm to use
	 */
	public DefaultPathBuilderFactory(PathBuilder builder) {
		this.pathBuilder = builder;
	}
	
	@Override
	public IAbstractionPathBuilder createPathBuilder(int maxThreadNum,
			IInfoflowCFG icfg) {
		switch (pathBuilder) {
		case Recursive :
			return new RecursivePathBuilder(icfg, maxThreadNum);
		case Threaded :
			return new ThreadedPathBuilder(maxThreadNum);
		case SemiThreaded :
			return new SemiThreadedPathBuilder(icfg, maxThreadNum);
		}
		throw new RuntimeException("Unsupported path building algorithm");
	}
	
}
