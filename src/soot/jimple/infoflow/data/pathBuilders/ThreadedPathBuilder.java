package soot.jimple.infoflow.data.pathBuilders;

import heros.solver.CountingThreadPoolExecutor;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowResults;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.data.SourceContextAndPath;
import soot.jimple.infoflow.util.MyConcurrentHashMap;
import soot.util.IdentityHashSet;

/**
 * Class for reconstructing abstraction paths from sinks to source
 * 
 * @author Steven Arzt
 */
public class ThreadedPathBuilder implements IAbstractionPathBuilder {
	
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final InfoflowResults results;
	private final CountingThreadPoolExecutor executor;
	
	private final MyConcurrentHashMap<Object, Set<Abstraction>> roots =
			new MyConcurrentHashMap<Object, Set<Abstraction>>();
	private MyConcurrentHashMap<Abstraction, Set<Abstraction>> successors = null;
	
	/**
	 * Creates a new instance of the {@link ThreadedPathBuilder} class
	 * @param results The result object in which to store the generated paths
	 * @param maxThreadNum The maximum number of threads to use
	 */
	public ThreadedPathBuilder(InfoflowResults results, int maxThreadNum) {
		this.results = results;
		
        int numThreads = Runtime.getRuntime().availableProcessors();
		this.executor = createExecutor(maxThreadNum == -1 ? numThreads
				: Math.min(maxThreadNum, numThreads));
	}
	
	/**
	 * Creates a new executor object for spawning worker threads
	 * @param numThreads The number of threads to use
	 * @return The generated executor
	 */
	private CountingThreadPoolExecutor createExecutor(int numThreads) {
		return new CountingThreadPoolExecutor
				(numThreads, Integer.MAX_VALUE, 30, TimeUnit.SECONDS,
				new LinkedBlockingQueue<Runnable>());
	}
	
	/**
	 * Task for only finding sources, not the paths towards them
	 * 
	 * @author Steven Arzt
	 */
	private class SourceFindingTask implements Runnable {
		private final AbstractionAtSink flagAbs;
		private final Abstraction abstraction;
		
		public SourceFindingTask(AbstractionAtSink flagAbs, Abstraction abstraction) {
			this.flagAbs = flagAbs;
			this.abstraction = abstraction;
		}
		
		private boolean addSuccessor(Abstraction parent, Abstraction child) {
			if (successors != null) {
				Set<Abstraction> succs = successors.putIfAbsentElseGet
						(parent, new IdentityHashSet<Abstraction>());
				return succs.add(child);
			}
			return false;
		}
		
		private void addRoot(Abstraction root) {
			if (roots != null) {
				Set<Abstraction> rootSet = roots.putIfAbsentElseGet
						(flagAbs, new IdentityHashSet<Abstraction>());
				rootSet.add(root);
			}
		}

		@Override
		public void run() {
			if (abstraction.getPredecessor() != null)
				addSuccessor(abstraction.getPredecessor(), abstraction);
			if (abstraction.getNeighbors() != null)
				for (Abstraction nb : abstraction.getNeighbors())
					addSuccessor(nb, abstraction);
			
			Set<SourceContextAndPath> scap = abstraction.getPaths();
			if (scap != null)
				return;
			scap = abstraction.getOrMakePathCache();
			
			if (abstraction.getSourceContext() != null) {
				// Register the result
				if (successors == null)
					results.addResult(flagAbs.getSinkValue(),
							flagAbs.getSinkStmt(),
							abstraction.getSourceContext().getValue(),
							abstraction.getSourceContext().getStmt(),
							abstraction.getSourceContext().getUserData(),
							Collections.<Stmt>emptyList());
				else
					scap.add(new SourceContextAndPath
							(abstraction.getSourceContext().getValue(),
							abstraction.getSourceContext().getStmt(),
							abstraction.getSourceContext().getUserData()).extendPath
									(abstraction.getSourceContext().getStmt()));
				addRoot(abstraction);
				
				// Sources may not have predecessors
				assert abstraction.getPredecessor() == null;
			}
			else
				executor.execute(new SourceFindingTask(flagAbs, abstraction.getPredecessor()));
			
			if (abstraction.getNeighbors() != null)
				for (Abstraction nb : abstraction.getNeighbors())
					executor.execute(new SourceFindingTask(flagAbs, nb));
		}
	}
	
	/**
	 * Task that extend paths down the data flow
	 * 
	 * @author Steven Arzt
	 */
	private class ExtendPathTask implements Runnable {
		
		private final Object flagAbs;
		private final Abstraction parent;
		private final boolean extendPath;
		
		public ExtendPathTask(Object flagAbs, Abstraction parent, boolean extendPath) {
			this.flagAbs = flagAbs;
			this.parent = parent;
			this.extendPath = extendPath;
		}
		
		@Override
		public void run() {
			Set<Abstraction> children = successors.get(parent);
			if (children == null)
				return;

			boolean added = false;
			for (Abstraction child : children) {
				Set<SourceContextAndPath> childScaps = child.getPaths();
				if (childScaps == null)
					continue;
				for (SourceContextAndPath scap : parent.getPaths())
					if (extendPath && child.getCurrentStmt() != null) {
						if (childScaps.add(scap.extendPath(child.getCurrentStmt()))) {
							added = true;
//							if (child.getCurrentStmt().toString().contains("iterator()"))
//								System.out.println(System.identityHashCode(flagAbs));
						}
					}
					else if (childScaps.add(scap))
						added = true;

				if (added)
					executor.execute(new ExtendPathTask(flagAbs, child, true/*!child.equals(parent)*/));
			}
			
//			if (childScaps == null)
//				childScaps = child.getOrMakePathCache(flagAbs);
			
		}

		/*
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((flagAbs == null) ? 0 : flagAbs.hashCode());
			result = prime * result + ((child == null) ? 0 : child.hashCode());
			result = prime * result + (extendPath ? 1231 : 1237);
			result = prime * result + ((parent == null) ? 0 : parent.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (!(obj instanceof ExtendPathTask))
				return false;
			ExtendPathTask other = (ExtendPathTask) obj;
			if (flagAbs == null) {
				if (other.flagAbs != null)
					return false;
			} else if (!flagAbs.equals(other.flagAbs))
				return false;
			if (child == null) {
				if (other.child != null)
					return false;
			} else if (!child.equals(other.child))
				return false;
			if (extendPath != other.extendPath)
				return false;
			if (parent == null) {
				if (other.parent != null)
					return false;
			} else if (!parent.equals(other.parent))
				return false;
			return true;
		}
		*/		
		
	}

	@Override
	public void computeTaintSources(final Set<AbstractionAtSink> res) {
		if (res.isEmpty())
			return;
		
		logger.debug("Running path reconstruction");
    	logger.info("Obtainted {} connections between sources and sinks", res.size());
    	
    	// Start the propagation tasks
    	int curResIdx = 0;
    	for (final AbstractionAtSink abs : res) {
    		logger.info("Building path " + ++curResIdx);
    		executor.execute(new SourceFindingTask(abs, abs.getAbstraction()));
    	}

    	try {
			executor.awaitCompletion();
		} catch (InterruptedException ex) {
			logger.error("Could not wait for path executor completion: {0}", ex.getMessage());
			ex.printStackTrace();
		}
    	
    	logger.debug("Path reconstruction done.");
	}
	
	@Override
	public void computeTaintPaths(final Set<AbstractionAtSink> res) {
		if (res.isEmpty())
			return;
		
		long beforePathTracking = System.nanoTime();
		successors = new MyConcurrentHashMap<Abstraction, Set<Abstraction>>();
		computeTaintSources(res);
		
    	// Start the path extensions tasks
		logger.info("Running path extension on {} roots", roots.size());
    	for (Object flagAbs : roots.keySet())
	    	for (Abstraction root : roots.get(flagAbs))
    			executor.execute(new ExtendPathTask(flagAbs, root, true));
    	
    	try {
			executor.awaitCompletion();
		} catch (InterruptedException ex) {
			logger.error("Could not wait for path executor completion: {0}", ex.getMessage());
			ex.printStackTrace();
		}
    	
    	logger.debug("Path extension done.");
    	
    	// Collect the results
    	for (final AbstractionAtSink abs : res) {
    		System.out.println(" - " + System.identityHashCode(abs));
    		for (SourceContextAndPath context : abs.getAbstraction().getPaths())
    			if (context.getSymbolic() == null) {
					results.addResult(abs.getSinkValue(), abs.getSinkStmt(),
							context.getValue(), context.getStmt(), context.getUserData(),
							context.getPath(), abs.getSinkStmt());
    			}
    	}
    	
    	successors = null;
    	logger.info("Path proecssing took {} seconds", (System.nanoTime() - beforePathTracking) / 1E9);
	}
	
	/**
	 * Shuts down the path processing
	 */
	public void shutdown() {
    	executor.shutdown();		
	}

	@Override
	public InfoflowResults getResults() {
		return this.results;
	}

}
