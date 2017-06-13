package soot.jimple.infoflow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Central configuration class for FlowDroid
 * 
 * @author Steven Arzt
 *
 */
public class InfoflowConfiguration {
	
    protected final Logger logger = LoggerFactory.getLogger(getClass());
    
    /**
	 * Enumeration containing the callgraph algorithms supported for the use with
	 * the data flow tracker
	 */
	public enum CallgraphAlgorithm {
		AutomaticSelection,
		CHA,
		VTA,
		RTA,
		SPARK,
		GEOM,
		OnDemand
	}
	
	/**
	 * Enumeration containing the aliasing algorithms supported by FlowDroid
	 */
	public enum AliasingAlgorithm {
		/**
		 * A fully flow-sensitive algorithm based on Andromeda
		 */
		FlowSensitive,
		/**
		 * A flow-insensitive algorithm based on Soot's point-to-sets
		 */
		PtsBased,
		/**
		 * Do not perform any alias analysis
		 */
		None,
		/**
		 * Perform lazy aliasing. Propagate every taint everywhere to on-demand
		 * check whether it aliases with any value access
		 */
		Lazy
	}

	/**
	 * Enumeration containing all possible modes of dead and irrelevant code
	 * elimination
	 */
	public enum CodeEliminationMode {
		/**
		 * Do not perform any code elimination before running the taint analysis
		 */
		NoCodeElimination,
		/**
		 * Perform an inter-procedural constant propagation and folding and then
		 * remove all code that is unreachable
		 */
		PropagateConstants,
		/**
		 * In addition to the inter-procedural constant propagation and folding,
		 * also remove live code that cannot potentially influence the outcome
		 * of the taint analysis
		 */
		RemoveSideEffectFreeCode
	}
	
	/**
	 * Enumeration containing the supported data flow solvers
	 */
	public enum DataFlowSolver {
		/**
		 * Use the Heros-based legacy solver
		 */
		@Deprecated
		Heros,
		
		/**
		 * Use a flow- and context-sensitive solver
		 */
		ContextFlowSensitive,
		
		/**
		 * Use a context-sensitive, but flow-insensitive solver
		 */
		FlowInsensitive
	}
	
	private int accessPathLength = 5;
	private boolean useRecursiveAccessPaths = true;
	private boolean useThisChainReduction = true;
	private static boolean pathAgnosticResults = true;
	private static boolean oneResultPerAccessPath = false;
	private static boolean mergeNeighbors = false;
	private boolean singleJoinPointAbstraction = false;
	
	private int stopAfterFirstKFlows = 0;
	private boolean enableImplicitFlows = false;
	private boolean enableStaticFields = true;
	private boolean enableExceptions = true;
	private boolean enableArraySizeTainting = true;
	private boolean flowSensitiveAliasing = true;
	private boolean enableTypeChecking = true;
	private boolean ignoreFlowsInSystemPackages = false;
	private boolean excludeSootLibraryClasses = false;
	private int maxThreadNum = -1;
	private boolean writeOutputFiles = false;
	private boolean logSourcesAndSinks = false;
	private boolean enableReflection = false;
	private boolean sequentialPathProcessing = false;
	
	private boolean inspectSources = false;
	private boolean inspectSinks = false;
	
	// this option will exclude the passed values to sources and sink into the xml output,
	// in order to improve the performance
	private boolean noPassedValues = false;
	// this option exclude the call graph fraction from the entry points to the source in
	// the xml output
	private boolean noCallGraphFraction = false; 
	private int maxCallersInOutputFile = 5;
	private long resultSerializationTimeout = 0;
	
	private CallgraphAlgorithm callgraphAlgorithm = CallgraphAlgorithm.AutomaticSelection;
	private AliasingAlgorithm aliasingAlgorithm = AliasingAlgorithm.FlowSensitive;
	private CodeEliminationMode codeEliminationMode = CodeEliminationMode.PropagateConstants;
	private DataFlowSolver dataFlowSolver = DataFlowSolver.ContextFlowSensitive;

	private boolean taintAnalysisEnabled = true;
	private boolean incrementalResultReporting = false;
	private long dataFlowTimeout = 0;
	private long pathReconstructionTimeout = 0;
	private boolean oneSourceAtATime = false;
	
	/**
	 * Merges the given configuration options into this configuration object
	 * @param config The configuration data to merge in
	 */
	public void merge(InfoflowConfiguration config) {
		this.accessPathLength = config.accessPathLength;
		this.useRecursiveAccessPaths = config.useRecursiveAccessPaths;
		this.useThisChainReduction = config.useThisChainReduction;
		this.singleJoinPointAbstraction = config.singleJoinPointAbstraction;
		
		this.stopAfterFirstKFlows = config.stopAfterFirstKFlows;
		this.enableImplicitFlows = config.enableImplicitFlows;
		this.enableStaticFields = config.enableStaticFields;
		this.enableExceptions = config.enableExceptions;
		this.enableArraySizeTainting = config.enableArraySizeTainting;
		this.flowSensitiveAliasing = config.flowSensitiveAliasing;
		this.enableTypeChecking = config.enableTypeChecking;
		this.ignoreFlowsInSystemPackages = config.ignoreFlowsInSystemPackages;
		this.excludeSootLibraryClasses = config.excludeSootLibraryClasses;
		this.maxThreadNum = config.maxThreadNum;
		this.writeOutputFiles = config.writeOutputFiles;
		this.logSourcesAndSinks = config.logSourcesAndSinks;
		this.enableReflection = config.enableReflection;
		this.sequentialPathProcessing = config.sequentialPathProcessing;
		
		this.callgraphAlgorithm = config.callgraphAlgorithm;
		this.aliasingAlgorithm = config.aliasingAlgorithm;
		this.codeEliminationMode = config.codeEliminationMode;		
		
		this.inspectSources = config.inspectSources;
		this.inspectSinks = config.inspectSinks;
		
		this.noPassedValues = config.noPassedValues;
		this.noCallGraphFraction = config.noCallGraphFraction;
		this.maxCallersInOutputFile = config.maxCallersInOutputFile;
		this.resultSerializationTimeout = config.resultSerializationTimeout;
		
		this.callgraphAlgorithm = config.callgraphAlgorithm;
		this.aliasingAlgorithm = config.aliasingAlgorithm;
		this.codeEliminationMode = config.codeEliminationMode;
		this.dataFlowSolver = config.dataFlowSolver;
		
		this.taintAnalysisEnabled = config.writeOutputFiles;
		this.incrementalResultReporting = config.incrementalResultReporting;
		this.dataFlowTimeout = config.dataFlowTimeout;
		this.pathReconstructionTimeout = config.pathReconstructionTimeout;
		this.oneSourceAtATime = config.oneSourceAtATime;
	}
	
	/**
	 * Gets the maximum depth of the access paths. All paths will be truncated
	 * if they exceed the given size.
	 * @param accessPathLength the maximum value of an access path.
	 */
	public int getAccessPathLength() {
		return accessPathLength;
	}
	
	/**
	 * Sets the maximum depth of the access paths. All paths will be truncated
	 * if they exceed the given size.
	 * @param accessPathLength the maximum value of an access path. If it gets longer than
	 *  this value, it is truncated and all following fields are assumed as tainted 
	 *  (which is imprecise but gains performance)
	 *  Default value is 5.
	 */
	public void setAccessPathLength(int accessPathLength) {
		this.accessPathLength = accessPathLength;
	}
	
	/**
	 * Sets whether results (source-to-sink connections) that only differ in their
	 * propagation paths shall be merged into a single result or not.
	 * @param pathAgnosticResults True if two results shall be regarded as equal
	 * if they connect the same source and sink, even if their propagation paths
	 * differ, otherwise false
	 */
	public static void setPathAgnosticResults(boolean pathAgnosticResults) {
		InfoflowConfiguration.pathAgnosticResults = pathAgnosticResults;
	}
	
	/**
	 * Gets whether results (source-to-sink connections) that only differ in their
	 * propagation paths shall be merged into a single result or not.
	 * @return True if two results shall be regarded as equal if they connect the
	 * same source and sink, even if their propagation paths differ, otherwise
	 * false
	 */
	public static boolean getPathAgnosticResults() {
		return InfoflowConfiguration.pathAgnosticResults;
	}
	
	/**
	 * Gets whether different results shall be reported if they only differ in
	 * the access path the reached the sink or left the source
	 * @return True if results shall also be distinguished based on access paths
	 */
	public static boolean getOneResultPerAccessPath() {
		return oneResultPerAccessPath;
	}
	
	/**
	 * Gets whether different results shall be reported if they only differ in
	 * the access path the reached the sink or left the source
	 * @param oneResultPerAP True if results shall also be distinguished based
	 * on access paths
	 */
	public static void setOneResultPerAccessPath(boolean oneResultPerAP) {
		oneResultPerAccessPath = oneResultPerAP;
	}
	
	/**
	 * Gets whether neighbors at the same statement shall be merged into a
	 * single abstraction
	 * @return True if equivalent neighbor shall be merged, otherwise false
	 */
	public static boolean getMergeNeighbors() {
		return mergeNeighbors;
	}
	
	/**
	 * Sets whether neighbors at the same statement shall be merged into a
	 * single abstraction
	 * @param value True if equivalent neighbor shall be merged, otherwise false
	 */
	public static void setMergeNeighbors(boolean value) {
		InfoflowConfiguration.mergeNeighbors = value;
	}
	
	/**
	 * Gets whether the data flow tracker shall only record one incoming
	 * abstraction per join point. This greatly reduces the memory requirements
	 * of the analysis. On the other hand, if data is tainted from two different
	 * sources, only one of them will be reported.
	 * @return True if only one incoming abstraction shall be reported per join
	 * point
	 */
	public boolean getSingleJoinPointAbstraction() {
		return this.singleJoinPointAbstraction;
	}
	
	/**
	 * Gets whether the data flow tracker shall only record one incoming
	 * abstraction per join point. This greatly reduces the memory requirements
	 * of the analysis. On the other hand, if data is tainted from two different
	 * sources, only one of them will be reported.
	 * @param singleJoinPointAbstraction True if only one incoming abstraction
	 * shall be reported per join point
	 */
	public void setSingleJoinPointAbstraction(boolean singleJoinPointAbstraction) {
		this.singleJoinPointAbstraction = singleJoinPointAbstraction;
	}

	/**
	 * Gets whether recursive access paths shall be reduced, e.g. whether we
	 * shall propagate a.[next].data instead of a.next.next.data.
	 * @return True if recursive access paths shall be reduced, otherwise false
	 */
	public boolean getUseRecursiveAccessPaths() {
		return useRecursiveAccessPaths;
	}

	/**
	 * Sets whether recursive access paths shall be reduced, e.g. whether we
	 * shall propagate a.[next].data instead of a.next.next.data.
	 * @param useRecursiveAccessPaths True if recursive access paths shall be
	 * reduced, otherwise false
	 */
	public void setUseRecursiveAccessPaths(boolean useRecursiveAccessPaths) {
		this.useRecursiveAccessPaths = useRecursiveAccessPaths;
	}
	
	/**
	 * Gets whether access paths pointing to outer objects using this$n shall be
	 * reduced, e.g. whether we shall propagate a.data instead of a.this$0.a.data.
	 * @return True if access paths including outer objects shall be reduced,
	 * otherwise false
	 */
	public boolean getUseThisChainReduction() {
		return this.useThisChainReduction;
	}

	/**
	 * Sets whether access paths pointing to outer objects using this$n shall be
	 * reduced, e.g. whether we shall propagate a.data instead of a.this$0.a.data.
	 * @param useThisChainReduction True if access paths including outer objects
	 * shall be reduced, otherwise false
	 */
	public void setUseThisChainReduction(boolean useThisChainReduction) {
		this.useThisChainReduction = useThisChainReduction;
	}

	/**
	 * Sets after how many flows the information flow analysis shall stop.
	 * @param stopAfterFirstKFlows number of flows after which to stop
	 */
	public void setStopAfterFirstKFlows(int stopAfterFirstKFlows) {
		this.stopAfterFirstKFlows = stopAfterFirstKFlows;
	}

	/**
	 * Gets after how many flows the information flow analysis shall stop.
	 * @return number of flows after which to stop
	 */
	public int getStopAfterFirstKFlows() {
		return stopAfterFirstKFlows;
	}
	
	/**
	 * Sets whether the information flow analysis shall stop after the first
	 * flow has been found
	 * @param stopAfterFirstFlow True if the analysis shall stop after the
	 * first flow has been found, otherwise false.
	 */
	public void setStopAfterFirstFlow(boolean stopAfterFirstFlow) {
		this.stopAfterFirstKFlows = stopAfterFirstFlow ? 1 : 0;
	}

	/**
	 * Gets whether the information flow analysis shall stop after the first
	 * flow has been found
	 * @return True if the information flow analysis shall stop after the first
	 * flow has been found, otherwise false
	 */
	public boolean getStopAfterFirstFlow() {
		return stopAfterFirstKFlows == 1;
	}
	
	/**
	 * Sets whether the implementations of source methods shall be analyzed as
	 * well
	 * @param inspect True if the implementations of source methods shall be
	 * analyzed as well, otherwise false
	 */
	public void setInspectSources(boolean inspect) {
		inspectSources = inspect;
	}
	
	/**
	 * Gets whether the implementations of source methods shall be analyzed as
	 * well
	 * @return True if the implementations of source methods shall be analyzed
	 * as well, otherwise false
	 */
	public boolean getInspectSources() {
		return inspectSources;
	}

	/**
	 * Sets whether the implementations of sink methods shall be analyzed as well
	 * @param inspect True if the implementations of sink methods shall be
	 * analyzed as well, otherwise false
	 */
	public void setInspectSinks(boolean inspect) {
		inspectSinks = inspect;
	}
	
	/**
	 * Sets whether the implementations of sink methods shall be analyzed as well
	 * @return True if the implementations of sink methods shall be analyzed as
	 * well, otherwise false
	 */
	public boolean getInspectSinks() {
		return inspectSinks;
	}

	/**
	 * Sets whether the solver shall consider implicit flows.
	 * @param enableImplicitFlows True if implicit flows shall be considered,
	 * otherwise false.
	 */
	public void setEnableImplicitFlows(boolean enableImplicitFlows) {
		this.enableImplicitFlows = enableImplicitFlows;
	}
	
	/**
	 * Gets whether the solver shall consider implicit flows.
	 * @return True if implicit flows shall be considered, otherwise false.
	 */
	public boolean getEnableImplicitFlows() {
		return enableImplicitFlows;
	}

	/**
	 * Sets whether the solver shall consider assignments to static fields
	 * @param enableStaticFields True if assignments to static fields shall be
	 * considered, otherwise false
	 */
	public void setEnableStaticFieldTracking(boolean enableStaticFields) {
		this.enableStaticFields = enableStaticFields;
	}
	
	/**
	 * Gets whether the solver shall trak assignments to static fields
	 * @return True if the solver shall trak assignments to static fields,
	 * otherwise false
	 */
	public boolean getEnableStaticFieldTracking() {
		return enableStaticFields;
	}
	
	/**
	 * Sets whether a flow sensitive aliasing algorithm shall be used
	 * @param flowSensitiveAliasing True if a flow sensitive aliasing algorithm
	 * shall be used, otherwise false
	 */
	public void setFlowSensitiveAliasing(boolean flowSensitiveAliasing) {
		this.flowSensitiveAliasing = flowSensitiveAliasing;
	}
	
	/**
	 * Gets whether a flow sensitive aliasing algorithm shall be used
	 * @return True if a flow sensitive aliasing algorithm shall be used,
	 * otherwise false
	 */
	public boolean getFlowSensitiveAliasing() {
		return flowSensitiveAliasing;
	}
		
	/**
	 * Sets whether the solver shall track taints of thrown exception objects
	 * @param enableExceptions True if taints associated with exceptions shall
	 * be tracked over try/catch construct, otherwise false
	 */
	public void setEnableExceptionTracking(boolean enableExceptions) {
		this.enableExceptions = enableExceptions;
	}
	
	/**
	 * Gets whether the solver shall track taints of thrown exception objects
	 * @return True if the solver shall track taints of thrown exception objects,
	 * otherwise false
	 */
	public boolean getEnableExceptionTracking() {
		return enableExceptions;
	}
	
	public void setEnableArraySizeTainting(boolean arrayLengthTainting) {
		this.enableArraySizeTainting = arrayLengthTainting;
	}
	
	public boolean getEnableArraySizeTainting() {
		return this.enableArraySizeTainting;
	}
	
	/**
	 * Sets the callgraph algorithm to be used by the data flow tracker
	 * @param algorithm The callgraph algorithm to be used by the data flow tracker
	 */
	public void setCallgraphAlgorithm(CallgraphAlgorithm algorithm) {
    	this.callgraphAlgorithm = algorithm;
	}
	
	/**
	 * Gets the callgraph algorithm to be used by the data flow tracker
	 * @return The callgraph algorithm to be used by the data flow tracker
	 */
	public CallgraphAlgorithm getCallgraphAlgorithm() {
		return callgraphAlgorithm;
	}
	
	/**
	 * Sets the aliasing algorithm to be used by the data flow tracker
	 * @param algorithm The aliasing algorithm to be used by the data flow tracker
	 */
	public void setAliasingAlgorithm(AliasingAlgorithm algorithm) {
    	this.aliasingAlgorithm = algorithm;
	}
	
	/**
	 * Gets the aliasing algorithm to be used by the data flow tracker
	 * @return The aliasing algorithm to be used by the data flow tracker
	 */
	public AliasingAlgorithm getAliasingAlgorithm() {
		return aliasingAlgorithm;
	}
	
	/**
	 * Sets whether type checking shall be done on casts and method calls
	 * @param enableTypeChecking True if type checking shall be performed,
	 * otherwise false
	 */
	public void setEnableTypeChecking(boolean enableTypeChecking) {
		this.enableTypeChecking = enableTypeChecking;
	}
	
	/**
	 * Gets whether type checking shall be done on casts and method calls
	 * @return True if type checking shall be performed, otherwise false
	 */
	public boolean getEnableTypeChecking() {
		return enableTypeChecking;
	}
	
	/**
	 * Sets whether flows starting or ending in system packages such as Android's
	 * support library shall be ignored.
	 * @param ignoreFlowsInSystemPackages True if flows starting or ending in
	 * system packages shall be ignored, otherwise false.
	 */
	public void setIgnoreFlowsInSystemPackages(boolean ignoreFlowsInSystemPackages) {
		this.ignoreFlowsInSystemPackages = ignoreFlowsInSystemPackages;
	}
	
	/**
	 * Gets whether flows starting or ending in system packages such as Android's
	 * support library shall be ignored.
	 * @return True if flows starting or ending in system packages shall be ignored,
	 * otherwise false.
	 */
	public boolean getIgnoreFlowsInSystemPackages() {
		return ignoreFlowsInSystemPackages;
	}
	
	/**
	 * Sets whether classes that are declared library classes in Soot shall be
	 * excluded from the data flow analysis, i.e., no flows shall be tracked
	 * through them
	 * @param excludeSootLibraryClasses True to exclude Soot library classes from
	 * the data flow analysis, otherwise false
	 */
	public void setExcludeSootLibraryClasses(boolean excludeSootLibraryClasses) {
		this.excludeSootLibraryClasses = excludeSootLibraryClasses;
	}
	
	/**
	 * Gets whether classes that are declared library classes in Soot shall be
	 * excluded from the data flow analysis, i.e., no flows shall be tracked
	 * through them
	 * @return True to exclude Soot library classes from the data flow analysis,
	 * otherwise false
	 */
	public boolean getExcludeSootLibraryClasses() {
		return this.excludeSootLibraryClasses;
	}
	
	/**
	 * Sets the maximum number of threads to be used by the solver. A value of -1
	 * indicates an unlimited number of threads, i.e., there will be as many threads
	 * as there are CPU cores on the machine.
	 * @param threadNum The maximum number of threads to be used by the solver,
	 * or -1 for an unlimited number of threads.
	 */
	public void setMaxThreadNum(int threadNum) {
		this.maxThreadNum = threadNum;
	}
	
	/**
	 * Gets the maximum number of threads to be used by the solver. A value of -1
	 * indicates an unlimited number of threads, i.e., there will be as many threads
	 * as there are CPU cores on the machine.
	 * @return The maximum number of threads to be used by the solver, or -1 for an
	 * unlimited number of threads.
	 */
	public int getMaxThreadNum() {
		return this.maxThreadNum;
	}
	
	/**
	 * Gets whether FlowDroid shall write the Jimple files to disk after the
	 * data flow analysis
	 * @return True if the Jimple files shall be written to disk after the data
	 * flow analysis, otherwise false
	 */
	public boolean getWriteOutputFiles() {
		return this.writeOutputFiles;
	}
	
	/**
	 * Gets whether FlowDroid shall write the Jimple files to disk after the
	 * data flow analysis
	 * @param writeOutputFiles True if the Jimple files shall be written to disk
	 * after the data flow analysis, otherwise false
	 */
	public void setWriteOutputFiles(boolean writeOutputFiles) {
		this.writeOutputFiles = writeOutputFiles;
	}
	
	/**
	 * Sets whether and how FlowDroid shall eliminate irrelevant code before
	 * running the taint propagation
	 * @param Mode the mode of dead and irrelevant code eliminiation to be
	 * used
	 */
	public void setCodeEliminationMode(CodeEliminationMode mode) {
		this.codeEliminationMode = mode;
	}
	
	/**
	 * Gets whether and how FlowDroid shall eliminate irrelevant code before
	 * running the taint propagation
	 * @return the mode of dead and irrelevant code elimination to be
	 * used
	 */
	public CodeEliminationMode getCodeEliminationMode() {
		return codeEliminationMode;
	}
	
	/**
	 * Gets the data flow solver to be used for the taint analysis
	 * @return The data flow solver to be used for the taint analysis
	 */
	public DataFlowSolver getDataFlowSolver() {
		return this.dataFlowSolver;
	}
	
	/**
	 * Sets the data flow solver to be used for the taint analysis
	 * @param solver The data flow solver to be used for the taint analysis
	 */
	public void setDataFlowSolver(DataFlowSolver solver) {
		this.dataFlowSolver = solver;
	}

	/**
	 * Gets whether the discovered sources and sinks shall be logged
	 * @return True if the discovered sources and sinks shall be logged,
	 * otherwise false
	 */
	public boolean getLogSourcesAndSinks() {
		return logSourcesAndSinks;
	}
	
	/**
	 * Sets whether the discovered sources and sinks shall be logged
	 * @param logSourcesAndSinks True if the discovered sources and sinks shall
	 * be logged, otherwise false
	 */
	public void setLogSourcesAndSinks(boolean logSourcesAndSinks) {
		this.logSourcesAndSinks = logSourcesAndSinks;
	}
	
	/**
	 * Gets whether reflective method calls shall be supported
	 * @return True if reflective method calls shall be supported, otherwise false
	 */
	public boolean getEnableReflection() {
		return this.enableReflection;
	}
	
	/**
	 * Sets whether reflective method calls shall be supported
	 * @param enableReflections True if reflective method calls shall be supported,
	 * otherwise false
	 */
	public void setEnableRefection(boolean enableReflections) {
		this.enableReflection = enableReflections;
	}
	
	/**
	 * Gets whether FlowDroid shall perform sequential path reconstruction instead
	 * of running all reconstruction tasks concurrently. This can reduce the memory
	 * consumption, but will likely take longer when memory is not an issue.
	 * @return True if the path reconstruction tasks shall be run sequentially,
	 * false for running them in parallel
	 */
	public boolean getSequentialPathProcessing() {
		return this.sequentialPathProcessing;
	}
	
	/**
	 * Sets whether FlowDroid shall perform sequential path reconstruction instead
	 * of running all reconstruction tasks concurrently. This can reduce the memory
	 * consumption, but will likely take longer when memory is not an issue.
	 * @param sequentialPathProcessing True if the path reconstruction tasks shall
	 * be run sequentially, false for running them in parallel
	 */
	public void setSequentialPathProcessing(boolean sequentialPathProcessing) {
		this.sequentialPathProcessing = sequentialPathProcessing;
	}

	/**
	 * Gets whether the taint analysis is enabled. If it is disabled, FlowDroid
	 * will initialize the Soot instance and then return immediately.
	 * @return True if data flow tracking shall be performed, false otherwise
	 */
	public boolean isTaintAnalysisEnabled() {
		return taintAnalysisEnabled;
	}

	/**
	 * Sets whether the taint analysis is enabled. If it is disabled, FlowDroid
	 * will initialize the Soot instance and then return immediately.
	 * @param taintAnalysisEnabled True if data flow tracking shall be performed,
	 * false otherwise
	 */
	public void setTaintAnalysisEnabled(boolean taintAnalysisEnabled) {
		this.taintAnalysisEnabled = taintAnalysisEnabled;
	}
	
	/**
	 * Gets whether the data flow results shall be reported incrementally instead
	 * of being only available after the full data flow analysis has been completed.
	 * @return True if incremental data flow results shall be available, otherwise
	 * false
	 */
	public boolean getIncrementalResultReporting() {
		return this.incrementalResultReporting;
	}
	
	/**
	 * Sets whether the data flow results shall be reported incrementally instead
	 * of being only available after the full data flow analysis has been completed.
	 * @param incrementalReporting True if incremental data flow results shall be
	 * available, otherwise false
	 */
	public void setIncrementalResultReporting(boolean incrementalReporting) {
		this.incrementalResultReporting = incrementalReporting;
	}
	
	/**
	 * Gets the timeout in seconds after which the taint analysis shall be
	 * aborted. This timeout only applies to the taint analysis itself, not
	 * to the path reconstruction that happens afterwards.
	 * @return The timeout in seconds after which the analysis shall be aborted
	 */
	public long getDataFlowTimeout() {
		return this.dataFlowTimeout;
	}
	
	/**
	 * Sets the timeout in seconds after which the analysis shall be aborted.
	 * This timeout only applies to the taint analysis itself, not to the path
	 * reconstruction that happens afterwards.
	 * @param timeout The timeout in seconds after which the analysis shall be
	 * aborted
	 */	
	public void setDataFlowTimeout(long timeout) {
		this.dataFlowTimeout = timeout;
	}
	
	/**
	 * Gets the timeout in seconds after which path reconstruction shall be
	 * aborted. This timeout is applied after the data flow analysis has been
	 * completed. If incremental path reconstruction is used, it is applied for
	 * the remaining path reconstruction after the data flow analysis has been
	 * completed. If incremental path reconstruction is not used, the timeout
	 * is applied to the complete path reconstruction phase, because it does not
	 * overlap with the data flow analysis phase in this case.
	 * @return The timeout in seconds after which the path reconstruction shall
	 * be aborted
	 */
	public long getPathReconstructionTimeout() {
		return this.pathReconstructionTimeout;
	}

	/**
	 * Sets the timeout in seconds after which path reconstruction shall be
	 * aborted. This timeout is applied after the data flow analysis has been
	 * completed. If incremental path reconstruction is used, it is applied for
	 * the remaining path reconstruction after the data flow analysis has been
	 * completed. If incremental path reconstruction is not used, the timeout
	 * is applied to the complete path reconstruction phase, because it does not
	 * overlap with the data flow analysis phase in this case.
	 * @param timeout The timeout in seconds after which the path reconstruction
	 * shall be aborted
	 */
	public void setPathReconstructionTimeout(long timeout) {
		this.pathReconstructionTimeout = timeout;
	}

	/**
	 * Gets whether FlowDroid shall exclude the passed values to sources and sinks 
	 * from the xml output from the analysis
	 *  @return True if FlowDroid shall exclude the passed values to sources and 
	 *  sinks, otherwise false
	 */
	public boolean getNoPassedValues(){
		return this.noPassedValues;
	}
	
	/**
	 * Sets whether to exclude the call graph fraction from the entry points to the source
	 * in the xml output
	 * @param noCallGraphFraction True if the call graph fraction from the entry points to
	 * the source shall be excluded from the xml output 
	 */
	public void setNoCallGraphFraction(boolean noCallGraphFraction){
		this.noCallGraphFraction = noCallGraphFraction;
	}
	
	/**
	 * Gets whether to exclude the call graph fraction from the entry points to the source
	 * in the xml output
	 * @return True if the call graph fraction from the entry points to the source shall
	 * be excluded from the xml output 
	 */
	public boolean getNoCallGraphFraction(){
		return noCallGraphFraction;
	}
	
	/**
	 * Specifies the maximum number of callers that shall be considered per node
	 * when writing out the call graph fraction from the entry point to the source.
	 * @param maxCallers The maximum number of callers to consider when writing
	 * out the call graph fraction between entry point and source
	 */
	public void setMaxCallersInOutputFile(int maxCallers) {
		this.maxCallersInOutputFile = maxCallers;
	}
	
	/**
	 * Gets the maximum number of callers that shall be considered per node when
	 * writing out the call graph fraction from the entry point to the source.
	 * @return The maximum number of callers to consider when writing out the call
	 * graph fraction between entry point and source
	 */
	public int getMaxCallersInOutputFile() {
		return this.maxCallersInOutputFile;
	}
	
	/**
	 * Sets the timeout in seconds for the result serialization process.
	 * Writing out the results is aborted if it takes longer than the given
	 * amount of time.
	 * @param timeout The maximum time for writing out the results in seconds
	 */
	public void setResultSerializationTimeout(long timeout) {
		this.resultSerializationTimeout = timeout;
	}
	
	/**
	 * Gets the timeout for the result serialization process in seconds. Writing
	 * out the results is aborted if it takes longer than the given amount of
	 * time.
	 * @result The maximum time for writing out the results in seconds
	 */
	public long getResultSerializationTimeout() {
		return this.resultSerializationTimeout;
	}
	
	/**
	 * Sets the option for exclusion of the passed values to sources and sinks 
	 * in the xml output 
	 * @param noPassedValues the boolean value whether passed values should 
	 * be excluded from the xml output 
	 */
	public void setNoPassedValues (boolean noPassedValues){
		this.noPassedValues=noPassedValues;
	}
	
	/**
	 * Gets whether one source shall be analyzed at a time instead of all
	 * sources together
	 * @return True if the analysis shall be run with one analysis at a time,
	 * false if the analysis shall be run with all sources together
	 */
	public boolean getOneSourceAtATime() {
		return this.oneSourceAtATime;
	}
	
	/**
	 * Sets whether one source shall be analyzed at a time instead of all
	 * sources together
	 * @param oneSourceAtATime True if the analysis shall be run with one
	 * analysis at a time, false if the analysis shall be run with all sources
	 * together
	 */
	public void setOneSourceAtATime(boolean oneSourceAtATime) {
		this.oneSourceAtATime = oneSourceAtATime;
	}

	/**
	 * Prints a summary of this data flow configuration
	 */
	public void printSummary() {
		if (!enableStaticFields)
			logger.warn("Static field tracking is disabled, results may be incomplete");
		if (!flowSensitiveAliasing)
			logger.warn("Using flow-insensitive alias tracking, results may be imprecise");
		if (enableImplicitFlows)
			logger.info("Implicit flow tracking is enabled");
		else
			logger.info("Implicit flow tracking is NOT enabled");
		if (enableExceptions)
			logger.info("Exceptional flow tracking is enabled");
		else
			logger.info("Exceptional flow tracking is NOT enabled");
		logger.info("Running with a maximum access path length of {}", getAccessPathLength());
		if (pathAgnosticResults)
			logger.info("Using path-agnostic result collection");
		else
			logger.info("Using path-sensitive result collection");
		if (useRecursiveAccessPaths)
			logger.info("Recursive access path shortening is enabled");
		else
			logger.info("Recursive access path shortening is NOT enabled");
		logger.info("Taint analysis enabled: " + taintAnalysisEnabled);
		if (oneSourceAtATime)
			logger.info("Running with one source at a time");
		logger.info("Using alias algorithm " + aliasingAlgorithm);
	}
	
}
