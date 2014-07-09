package soot.jimple.infoflow.data.pathBuilders;

import heros.solver.CountingThreadPoolExecutor;
import heros.solver.Pair;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowResults;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.data.SourceContextAndPath;
import soot.jimple.infoflow.solver.IInfoflowCFG;
import soot.util.IdentityHashSet;

/**
 * Recursive algorithm for reconstructing abstraction paths from sink to source
 * 
 * @author Steven Arzt
 */
public class RecursivePathBuilder extends AbstractAbstractionPathBuilder {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final InfoflowResults results = new InfoflowResults();
	private final CountingThreadPoolExecutor executor;
    
	private static int lastTaskId = 0;

	/**
     * Creates a new instance of the {@link RecursivePathBuilder} class
	 * @param maxThreadNum The maximum number of threads to use
     */
    public RecursivePathBuilder(IInfoflowCFG icfg, int maxThreadNum) {
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
	 * Gets the path of statements from the source to the current statement
	 * with which this abstraction is associated. If this path is ambiguous,
	 * a single path is selected randomly.
	 * @param taskId A unique ID identifying this path search task
	 * @param curAbs The current abstraction from which to start the search
	 * @param reconstructPaths True if the path to the source shall be
	 * reconstructed, false if only the source as such shall be found
	 * @return The path from the source to the current statement
	 */
	private Set<SourceContextAndPath> getPaths(int taskId, Abstraction curAbs,
			boolean reconstructPaths, Stack<Pair<Stmt, Set<Abstraction>>> callStack) {
		Set<SourceContextAndPath> cacheData = new HashSet<SourceContextAndPath>();
		
		Pair<Stmt, Set<Abstraction>> stackTop = callStack.isEmpty() ? null : callStack.peek();
		if (stackTop != null) {
			Set<Abstraction> callAbs = stackTop.getO2();
			if (!callAbs.add(curAbs))
				return Collections.emptySet();
		}
		
		// If the current statement is a source, we have found a path root
		if (curAbs.getSourceContext() != null) {
			// Construct the path root
			SourceContextAndPath sourceAndPath = new SourceContextAndPath
					(curAbs.getSourceContext().getValue(),
							curAbs.getSourceContext().getStmt(),
							curAbs.getSourceContext().getUserData()).extendPath
									(curAbs.getSourceContext().getStmt());
			cacheData.add(sourceAndPath);
			
			// Sources may not have predecessors
			assert curAbs.getPredecessor() == null;
		}
		else {
			// If we have a corresponding call site for the current return
			// statement, we need to add it to the call stack.
			Stack<Pair<Stmt, Set<Abstraction>>> newCallStack = new Stack<Pair<Stmt, Set<Abstraction>>>();
			newCallStack.addAll(callStack);
			if (curAbs.getCorrespondingCallSite() != null/* && curAbs.isAbstractionActive()*/)
				newCallStack.push(new Pair<Stmt, Set<Abstraction>>(curAbs.getCorrespondingCallSite(),
						new IdentityHashSet<Abstraction>()));
			
/*			boolean isMethodEnter = curAbs.getCurrentStmt() != null
					&& (curAbs.isAbstractionActive()
							? curAbs.getCurrentStmt().containsInvokeExpr()
							: false
						);
*/
			boolean isMethodEnter = curAbs.getCurrentStmt() != null
					&& curAbs.getCurrentStmt().containsInvokeExpr();
			
			// If the current statement enters a method, we have to check the call stack.
			// We only accept the path if the call site to which we return matches the
			// call site at which we have entered the callee. We accept the call stack
			// to run empty if we follow returns past seeds.
			boolean scanPreds = true;
			if (isMethodEnter)
				if (!newCallStack.isEmpty()) {
					Pair<Stmt, Set<Abstraction>> newStackTop = newCallStack.isEmpty() ? null : newCallStack.peek();
					if (newStackTop.getO1() != null) {
						if (curAbs.getCurrentStmt() != newStackTop.getO1())
							scanPreds = false;
						newCallStack.pop();
					}
				}
			
			if (scanPreds) {
				// Otherwise, we have to check the predecessor
				for (SourceContextAndPath curScap : getPaths(taskId,
						curAbs.getPredecessor(), reconstructPaths, newCallStack)) {
					SourceContextAndPath extendedPath = (curAbs.getCurrentStmt() == null || !reconstructPaths)
							? curScap : curScap.extendPath(curAbs.getCurrentStmt());
					cacheData.add(extendedPath);
				}
			}
		}
		
		if (curAbs.getNeighbors() != null)
			for (Abstraction nb : curAbs.getNeighbors())
				for (SourceContextAndPath path : getPaths(taskId, nb, reconstructPaths, callStack))
					cacheData.add(path);
		
		return Collections.unmodifiableSet(cacheData);
	}
	
	/**
	 * Computes the path of tainted data between the source and the sink
	 * @param computeResultPaths True if the paths shall be computed as well,
	 * false if only the sources as such shall be found
	 * @param res The data flow tracker results
	 */
	private void computeTaintPathsInternal(final boolean computeResultPaths,
			final Set<AbstractionAtSink> res) {   	
		logger.debug("Running path reconstruction");
    	logger.info("Obtainted {} connections between sources and sinks", res.size());
    	int curResIdx = 0;
    	for (final AbstractionAtSink abs : res) {
    		logger.info("Building path " + ++curResIdx);
    		executor.execute(new Runnable() {
				
				@Override
				public void run() {
					Stack<Pair<Stmt, Set<Abstraction>>> initialStack = new Stack<Pair<Stmt, Set<Abstraction>>>();
					initialStack.push(new Pair<Stmt, Set<Abstraction>>(null, new IdentityHashSet<Abstraction>()));
		    		for (SourceContextAndPath context : getPaths(lastTaskId++,
		    				abs.getAbstraction(), computeResultPaths,
		    				initialStack))
						results.addResult(abs.getSinkValue(), abs.getSinkStmt(),
								context.getValue(), context.getStmt(), context.getUserData(),
								context.getPath(), abs.getSinkStmt());
				}
				
			});
    		
    	}
    	
    	try {
			executor.awaitCompletion();
		} catch (InterruptedException ex) {
			logger.error("Could not wait for path executor completion: {0}", ex.getMessage());
			ex.printStackTrace();
		}
    	executor.shutdown();
    	logger.debug("Path reconstruction done.");
	}

	@Override
	public void computeTaintSources(Set<AbstractionAtSink> res) {
		computeTaintPathsInternal(false, res);
	}

	@Override
	public void computeTaintPaths(Set<AbstractionAtSink> res) {
		computeTaintPathsInternal(true, res);
	}

	@Override
	public InfoflowResults getResults() {
		return this.results;
	}

	@Override
	public void shutdown() {
	}
	
}
