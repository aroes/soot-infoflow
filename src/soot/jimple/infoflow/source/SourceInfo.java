package soot.jimple.infoflow.source;

import soot.jimple.InstanceFieldRef;
import soot.jimple.infoflow.data.AccessPath;

/**
 * Class containing additional information about a source. Users of FlowDroid
 * can derive from this class when implementing their own SourceSinkManager
 * to associate additional information with a source.
 * 
 * @author Steven Arzt, Daniel Magin
 */
public class SourceInfo {
	
	@Deprecated
	private boolean taintSubFields = true;
	private Object userData = null;
	private final AccessPathBundle bundle;
	
	/**
	 * Creates a new instance of the {@link SourceInfo} class
	 * @param taintSubFields True if all fields reachable through the source
	 * shall also be considered as tainted, false if only the source as such
	 * shall be tainted.
	 */
	@Deprecated
	public SourceInfo(boolean taintSubFields) {
		this(taintSubFields, null);
	}
	
	/**
	 * Creates a new instance of the {@link SourceInfo} class
	 * @param taintSubFields True if all fields reachable through the source
	 * shall also be considered as tainted, false if only the source as such
	 * shall be tainted.
	 * @param userData Additional user data to be propagated with the source
	 * @author Daniel Magin
	 */
	@Deprecated
	public SourceInfo(boolean taintSubFields, Object userData) {
		this(taintSubFields, userData, null);
	}
	
	/**
	 * Creates a new instance of the {@link SourceInfo} class
	 * @param bundle Information about access paths tainted by this source
	 * @author Daniel Magin
	 */
	public SourceInfo(AccessPathBundle bundle){
		this(true, null, bundle);
	}
	
	/**
	 * Creates a new instance of the {@link SourceInfo} class
	 * @param userData Additional user data to be propagated with the source
	 * @param bundle Information about access paths tainted by this source
	 * @author Daniel Magin
	 */
	public SourceInfo(Object userData, AccessPathBundle bundle){
		this(true, userData, bundle);
	}

	/**
	 * Creates a new instance of the {@link SourceInfo} class
	 * @param taintSubFields True if all fields reachable through the source
	 * shall also be considered as tainted, false if only the source as such
	 * shall be tainted.
	 * @param userData Additional user data to be propagated with the source
	 * @param bundle Information about access paths tainted by this source
	 * @author Daniel Magin
	 */
	public SourceInfo(boolean taintSubFields, Object userData, AccessPathBundle bundle){
		this.taintSubFields = taintSubFields;
		this.userData = userData;
		this.bundle = (bundle != null) ? bundle: new AccessPathBundle(null,null,null,null,null);
	}

	@Override
	public int hashCode() {
		return 31 * (taintSubFields ? 1 : 0)
				+ 31 * (this.userData == null ? 0 : this.userData.hashCode())
				+ 31 * (this.bundle == null ? 0 : this.bundle.hashCode());
	}
	
	@Override
	public boolean equals(Object other) {
		if (other == null || !(other instanceof SourceInfo))
			return false;
		SourceInfo otherInfo = (SourceInfo) other;
		if (taintSubFields != otherInfo.taintSubFields)
			return false;
		if (this.userData == null) {
			if (otherInfo.userData != null)
				return false;
		}
		if(this.bundle == null){
			if(otherInfo.userData != null){
				return false;
			}
		}
		else if (!this.userData.equals(otherInfo.userData))
			return false;
		else if(!this.bundle.equals(otherInfo.bundle))
			return false;
		return true;
	}

	/**
	 * Gets whether all fields reachable through the source shall also be
	 * considered as tainted.
	 * @return True if all fields reachable through the source shall also
	 * be considered as tainted, false if only the source as such shall be
	 * tainted.
	 */
	@Deprecated
	public boolean getTaintSubFields() {
		return taintSubFields;
	}
	
	/**
	 * Gets the user data to be tracked together with this source
	 * @return The user data to be tracked together with this source
	 */
	public Object getUserData() {
		return this.userData;
	}

	/**
	 * Returns all access paths of the base object which are tainted by this method
	 * or null if there is no taint for base or if the  method is static
	 * @return all tainted access paths of the base object
	 * @author Daniel Magin
	 */
	public AccessPath[] getBaseAPs(){
		return  this.bundle.getSourceBaseAPs();
	}
	
	/**
	 * Returns all access paths of the return object which are tainted by this method
	 * or null if there is no taint for return or if the  method is void
	 * @return all tainted access paths of the return object
	 * @author Daniel Magin
	 */
	public AccessPath[] getReturnAPs(){
		return this.bundle.getSourceReturnAPs();
	}
	
	/**
	 * Returns all access paths of the parameter object which are tainted by this method
	 * or null if there is no taint for the given parameter.
	 * @param index of the parameter counted from 0
	 * @return all tainted access paths of the given parameter object
	 * @author Daniel Magin
	 */
	public AccessPath[] getParameterAPs(int index){
		return this.bundle.getSourceParameterAPs(index);
	}
	
}
