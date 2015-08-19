package soot.jimple.infoflow.problems.rules;

import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.data.Abstraction;

/**
 * Abstract base class for all taint propagation rules
 * 
 * @author Steven Arzt
 *
 */
public abstract class AbstractTaintPropagationRule implements
		ITaintPropagationRule {
	
	private final InfoflowManager manager;
	private final Aliasing aliasing;
	private final Abstraction zeroValue;
	
	public AbstractTaintPropagationRule(InfoflowManager manager,
			Aliasing aliasing, Abstraction zeroValue) {
		this.manager = manager;
		this.aliasing = aliasing;
		this.zeroValue = zeroValue;
	}
	
	protected InfoflowManager getManager() {
		return this.manager;
	}
	
	protected Aliasing getAliasing() {
		return this.aliasing;
	}
	
	protected Abstraction getZeroValue() {
		return this.zeroValue;
	}
	
}
