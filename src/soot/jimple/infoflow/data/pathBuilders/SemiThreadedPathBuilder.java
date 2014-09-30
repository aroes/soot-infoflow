package soot.jimple.infoflow.data.pathBuilders;

import heros.solver.CountingThreadPoolExecutor;
import heros.solver.Pair;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowResults;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.data.SourceContextAndPath;
import soot.jimple.infoflow.solver.IInfoflowCFG;

/**
 * Class for reconstructing abstraction paths from sinks to source
 * 
 * @author Steven Arzt
 */
public class SemiThreadedPathBuilder extends AbstractAbstractionPathBuilder {
	
	private AtomicInteger propagationCount = null;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final InfoflowResults results = new InfoflowResults();
	private final CountingThreadPoolExecutor executor;
		
	/**
	 * Creates a new instance of the {@link SemiThreadedPathBuilder} class
	 * @param maxThreadNum The maximum number of threads to use
	 */
	public SemiThreadedPathBuilder(IInfoflowCFG icfg, int maxThreadNum) {
		super(icfg);
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
		private final Deque<Abstraction> abstractionQueue = new ArrayDeque<Abstraction>();
		
		public SourceFindingTask(Abstraction abstraction) {
			this.abstractionQueue.push(abstraction);
		}
		
		@Override
		public void run() {
			while (!abstractionQueue.isEmpty()) {
				Abstraction abstraction = abstractionQueue.pop();
				propagationCount.incrementAndGet();
								
				if (abstraction.getPredecessor() == null) {
					// If we have no predecessors, this must be a source
					assert abstraction.getSourceContext() != null;
					Set<SourceContextAndPath> paths = abstraction.getPaths();
					
					// Register the result
					for (SourceContextAndPath scap : paths) {
						scap = scap.extendPath(abstraction.getSourceContext().getStmt());
						results.addResult(scap.getValue(),
								scap.getStmt(),
								abstraction.getSourceContext().getValue(),
								abstraction.getSourceContext().getStmt(),
								abstraction.getSourceContext().getUserData(),
								scap.getPath());
					}
				}
				else {
					Set<SourceContextAndPath> paths = abstraction.getPaths();
					Abstraction pred = abstraction.getPredecessor();
					if (pred != null) {
						for (SourceContextAndPath scap : paths) {
							// Process the predecessor
							if (processPredecessor(scap, pred))
								// Schedule the predecessor
								abstractionQueue.add(pred);
							
							// Process the predecessor's neighbors
							if (pred.getNeighbors() != null)
								for (Abstraction neighbor : pred.getNeighbors())
									if (processPredecessor(scap, neighbor))
										// Schedule the predecessor
										abstractionQueue.add(neighbor);
						}
					}
				}
			}
		}

		private boolean processPredecessor(SourceContextAndPath scap, Abstraction pred) {
			// If we have already seen this predecessor, we skip it
			if (!scap.putAbstractionOnCallStack(pred))
				return false;
			
			// If we enter a method, we put it on the stack
			Stmt callSite = null;
			if (pred.getCurrentStmt() != null
					&& pred.getCorrespondingCallSite() != null
					&& pred.getCurrentStmt() != pred.getCorrespondingCallSite()) {
				callSite = pred.getCorrespondingCallSite();
			}
				
			SourceContextAndPath extendedScap;
			if (pred.getCurrentStmt() != null)
				extendedScap = scap.extendPath(pred.getCurrentStmt(), callSite);
			else
				extendedScap = scap;
				
			// Do we process a method return?
			if (pred.getCurrentStmt() != null
					&& pred.getCorrespondingCallSite() == null
					&& pred.getCurrentStmt().containsInvokeExpr()) {
				// Pop the top item off the call stack. This gives us the item
				// and the new SCAP without the item we popped off.
				Pair<SourceContextAndPath, Pair<Stmt, Set<Abstraction>>> pathAndItem =
						extendedScap.popTopCallStackItem();
				Pair<Stmt, Set<Abstraction>> topCallStackItem = pathAndItem.getO2();
				if (topCallStackItem != null && topCallStackItem.getO1() != null) {
					// Make sure that we don't follow an unrealizable path
					if (topCallStackItem.getO1() != pred.getCurrentStmt())
						return false;
						
					// We have returned from a function
					extendedScap = pathAndItem.getO1();
				}
			}
				
			// Add the new path
			return pred.addPathElement(extendedScap);
		}
	}
	
	@Override
	public void computeTaintSources(final Set<AbstractionAtSink> res) {
		if (res.isEmpty())
			return;
		
		long beforePathTracking = System.nanoTime();
		propagationCount = new AtomicInteger();
    	logger.info("Obtainted {} connections between sources and sinks", res.size());
    	
    	// Start the propagation tasks
    	int curResIdx = 0;
    	for (final AbstractionAtSink abs : res) {
   			SourceContextAndPath scap = new SourceContextAndPath(
   					abs.getSinkValue(), abs.getSinkStmt());
   			scap = scap.extendPath(abs.getSinkStmt());
   			abs.getAbstraction().addPathElement(scap);
    		
    		logger.info("Building path " + ++curResIdx);
    		executor.execute(new SourceFindingTask(abs.getAbstraction()));
    	}

    	try {
			executor.awaitCompletion();
		} catch (InterruptedException ex) {
			logger.error("Could not wait for path executor completion: {0}", ex.getMessage());
			ex.printStackTrace();
		}
    	
    	logger.info("Path processing took {} seconds in total for {} edges",
    			(System.nanoTime() - beforePathTracking) / 1E9, propagationCount.get());
	}
	
	@Override
	public void computeTaintPaths(final Set<AbstractionAtSink> res) {
		computeTaintSources(res);
	}
	
	@Override
	public void shutdown() {
    	executor.shutdown();		
	}

	@Override
	public InfoflowResults getResults() {
		return this.results;
	}

}
