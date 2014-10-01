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
		ContextSensitive
	}
	
	private final PathBuilder pathBuilder;
	
	/**
	 * Creates a new instance of the {@link DefaultPathBuilderFactory} class
	 */
	public DefaultPathBuilderFactory() {
		this(PathBuilder.ContextSensitive);
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
		}
		throw new RuntimeException("Unsupported path building algorithm");
	}
	
}
