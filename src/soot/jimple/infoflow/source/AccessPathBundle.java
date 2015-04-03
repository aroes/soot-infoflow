package soot.jimple.infoflow.source;

import soot.jimple.infoflow.data.AccessPath;

/**
 * A class to handle all access paths of sources and sinks for a certain method.
 * 
 * @author Daniel Magin, Joern Tillmanns
 *
 */
public class AccessPathBundle {

	private final AccessPath[] baseSource, baseSink, retSource;
	private final AccessPath[][] parameterSource, parameterSink;

	/**
	 * Creates empty Bundle, where all AccessPathsArrays are null.
	 * 
	 */
	public AccessPathBundle() {
		this(null, null, null, null, null);
	}

	/**
	 * Sets all but the sourceReturnAPs to null. Useful for the most source
	 * methods.
	 * 
	 * @param sourceReturnAPs
	 *            all access paths of the return object which will be tainted by
	 *            this source.
	 */
	public AccessPathBundle(AccessPath[] sourceReturnAPs) {
		this(null, null, null, null, sourceReturnAPs);
	}

	public AccessPathBundle(AccessPath[] sourceBaseAPs, AccessPath[][] sourceParamterAPs, AccessPath[] sourceReturnAPs) {
		this(sourceBaseAPs, null, sourceParamterAPs, null, sourceReturnAPs);
	}

	/**
	 * Sets all but the sinkParameterAPs to null. Useful for the most sink
	 * methods.
	 * 
	 * @param sinkParamterAPs
	 *            all access paths of all parameters which will be leaked by
	 *            this sink. The index of the array represents the index of the
	 *            parameter. The first parameter has the index 0.
	 */
	public AccessPathBundle(AccessPath[][] sinkParamterAPs) {
		this(null, null, null, sinkParamterAPs, null);
	}

	public AccessPathBundle(AccessPath[] sinkBaseAPs, AccessPath[][] sinkParamterAPs) {
		this(null, sinkBaseAPs, null, sinkParamterAPs, null);
	}

	/**
	 * If there are no source or sink access paths for the base, return or any parameter, just set it to null.
	 * @param sourceBaseAPs all access paths of the base object which will be tainted by this source.
	 * @param sinkBaseAPs all access paths  of the base object which will be leaked by this sink.
	 * @param sourceParameterAPs all access paths of all parameters which will be tainted by this source.
	 * The index of the array represents the index of the parameter. The first parameter has the index 0. 							 
	 * @param sinkParameterAPs all access paths of all parameters which will be leaked by this sink.
	 * The index of the array represents the index of the parameter. The first parameter has the index 0.
	 * @param sourceReturnAPs all access paths of the return object which will be tainted by this source.
	 * @param sinkReturnAPs all access paths  of the return object which will be leaked by this sink.
	 */
	public AccessPathBundle(AccessPath[] sourceBaseAPs, AccessPath[] sinkBaseAPs, AccessPath[][] sourceParameterAPs,
			AccessPath[][] sinkParameterAPs, AccessPath[] sourceReturnAPs) {
		this.baseSource = sourceBaseAPs;
		this.baseSink = sinkBaseAPs;
		this.retSource = sourceReturnAPs;
		this.parameterSource = sourceParameterAPs;
		this.parameterSink = sinkParameterAPs;
	}
	
	/**
	 * Getter for the array of access paths of the base object tainted by this source
	 * @return access paths of the base object tainted by this source or null if there are none
	 */
	public AccessPath[] getSourceBaseAPs(){
		return this.baseSource;
	}
	
	/**
	 * Getter for the array of access paths of the return object tainted by this source
	 * @return access paths of the return object tainted by this source or null if there are none
	 */
	public AccessPath[] getSourceReturnAPs(){
		return this.retSource;
	}
	
	/**
	 * Getter for the array of access paths of a certain parameter object tainted by this source
	 * @param index the parameter index (counted from 0)
	 * @return access paths of the parameter object with the given index tainted by this source or null if there are none
	 */
	public AccessPath[] getSourceParameterAPs(int index){
		return (this.parameterSource != null) ? this.parameterSource[index] : null;
	}
	
	/**
	 * Getter for the array of access paths of the base object leaking in this sink
	 * @return access paths of the base object leaking in this sink or null if there are none
	 */
	public AccessPath[] getSinkBaseAPs(){
		return this.baseSink;
	}
	
	/**
	 * Getter for the array of access paths of a certain parameter object leaking in this sink
	 * @param index the parameter index (counted from 0)
	 * @return access paths of the parameter object with the given index leaking in this sink or null if there are none
	 */
	public AccessPath[] getSinkParamterAPs(int index){
		return (this.parameterSink != null) ? this.parameterSink[index] : null;
	}
	
	/**
	 * Getter for the number of parameters for this source
	 * @return the number of parameters of this source
	 */
	public int getSourceParameterCount(){
		return this.parameterSource != null ? this.parameterSource.length : 0;
	}
	
	/**
	 * Getter for the number of parameters for this sink
	 * @return the number of parameters of this sink
	 */
	public int getSinkParameterCount(){
		return this.parameterSink != null ? this.parameterSink.length : 0;
	}
}
