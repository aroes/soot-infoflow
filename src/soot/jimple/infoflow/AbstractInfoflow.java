package soot.jimple.infoflow;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import soot.jimple.infoflow.cfg.BiDirICFGFactory;
import soot.jimple.infoflow.cfg.DefaultBiDiICFGFactory;
import soot.jimple.infoflow.entryPointCreators.DefaultEntryPointCreator;
import soot.jimple.infoflow.entryPointCreators.IEntryPointCreator;
import soot.jimple.infoflow.handlers.PreAnalysisHandler;
import soot.jimple.infoflow.nativ.DefaultNativeCallHandler;
import soot.jimple.infoflow.nativ.INativeCallHandler;
import soot.jimple.infoflow.source.DefaultSourceSinkManager;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;

/**
 * Abstract base class for all data/information flow analyses in FlowDroid
 * @author Steven Arzt
 *
 */
public abstract class AbstractInfoflow implements IInfoflow {
	
	protected InfoflowConfiguration config = new InfoflowConfiguration();
	protected ITaintPropagationWrapper taintWrapper;
	protected INativeCallHandler nativeCallHandler = new DefaultNativeCallHandler();
	
	protected final BiDirICFGFactory icfgFactory;
	protected Collection<PreAnalysisHandler> preProcessors = Collections.emptyList();
	    
    /**
     * Creates a new instance of the abstract info flow problem
     */
    public AbstractInfoflow() {
    	this(null);
    }

    /**
     * Creates a new instance of the abstract info flow problem
     * @param icfgFactory The interprocedural CFG to be used by the InfoFlowProblem
     */
    public AbstractInfoflow(BiDirICFGFactory icfgFactory) {
    	if (icfgFactory == null)
    		this.icfgFactory = new DefaultBiDiICFGFactory();
    	else
    		this.icfgFactory = icfgFactory;
    }
    
    @Override
	public InfoflowConfiguration getConfig() {
    	return this.config;
    }

    @Override
    public void setConfig(InfoflowConfiguration config) {
    	this.config = config;
    }

    @Override
	public void setTaintWrapper(ITaintPropagationWrapper wrapper) {
		taintWrapper = wrapper;
	}
    
    @Override
    public void setNativeCallHandler(INativeCallHandler handler) {
    	this.nativeCallHandler = handler;
    }
    
    @Override
    public ITaintPropagationWrapper getTaintWrapper() {
    	return taintWrapper;
    }
    
	@Override
	public void setPreProcessors(Collection<PreAnalysisHandler> preprocessors) {
        this.preProcessors = preprocessors;
	}

	@Override
	public void computeInfoflow(String appPath, String libPath,
			IEntryPointCreator entryPointCreator,
			List<String> sources, List<String> sinks) {
		this.computeInfoflow(appPath, libPath, entryPointCreator,
				new DefaultSourceSinkManager(sources, sinks));
	}

	@Override
	public void computeInfoflow(String appPath, String libPath,
			Collection<String> entryPoints, 
			Collection<String> sources,
			Collection<String> sinks) {
		this.computeInfoflow(appPath, libPath, new DefaultEntryPointCreator(entryPoints),
				new DefaultSourceSinkManager(sources, sinks));
	}

	@Override
	public void computeInfoflow(String libPath, String appPath,
			String entryPoint, Collection<String> sources, Collection<String> sinks) {
		this.computeInfoflow(appPath, libPath, entryPoint, new DefaultSourceSinkManager(sources, sinks));
	}
	
}
