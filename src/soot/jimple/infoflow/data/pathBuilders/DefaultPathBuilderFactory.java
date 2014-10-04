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
		/**
		 * Simple context-insensitive, single-threaded, recursive approach to
		 * path reconstruction. Low overhead for small examples, but does not
		 * scale.
		 */
		Recursive,
		/**
		 * Highly precise context-sensitive path reconstruction approach. For
		 * a large number of paths or complex programs, it may be slow.
		 */
		ContextSensitive,
		/**
		 * A context-insensitive path reconstruction algorithm. It scales well,
		 * but may introduce false positives.
		 */
		ContextInsensitive,
		/**
		 * Very fast context-insensitive implementation that only finds
		 * source-to-sink connections, but no paths.
		 */
		ContextInsensitiveSourceFinder
	}
	
	private final PathBuilder pathBuilder;
	
	/**
	 * Creates a new instance of the {@link DefaultPathBuilderFactory} class
	 */
	public DefaultPathBuilderFactory() {
		this(PathBuilder.ContextInsensitiveSourceFinder);
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
		case ContextSensitive :
			return new ContextSensitivePathBuilder(icfg, maxThreadNum);
		case ContextInsensitive :
			return new ContextInsensitivePathBuilder(icfg, maxThreadNum);
		case ContextInsensitiveSourceFinder :
			return new ContextInsensitiveSourceFinder(maxThreadNum);
		}
		throw new RuntimeException("Unsupported path building algorithm");
	}
	
}
