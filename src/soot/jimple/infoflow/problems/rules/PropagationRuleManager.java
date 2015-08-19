package soot.jimple.infoflow.problems.rules;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.data.Abstraction;

/**
 * Manager class for all propagation rules
 * 
 * @author Steven Arzt
 *
 */
public class PropagationRuleManager {
	
	protected final InfoflowManager manager;
	protected final Aliasing aliasing;
	protected final Abstraction zeroValue;
	private final List<ITaintPropagationRule> rules = new ArrayList<>();
	
	public PropagationRuleManager(InfoflowManager manager, Aliasing aliasing,
			Abstraction zeroValue) {
		this.manager = manager;
		this.aliasing = aliasing;
		this.zeroValue = zeroValue;
		
		rules.add(new SourcePropagationRule(manager, aliasing, zeroValue));
	}
	
	/**
	 * Applies all rules to the normal flow function
	 * @param d1 The context abstraction
	 * @param source The incoming taint to propagate over the given statement
	 * @param stmt The statement to which to apply the rules
	 * @return The collection of outgoing taints
	 */
	public Set<Abstraction> applyNormalFlowFunction(Abstraction d1,
			Abstraction source, Stmt stmt) {
		Set<Abstraction> res = null;
		
		for (ITaintPropagationRule rule : rules) {
			Collection<Abstraction> ruleOut = rule.propagateNormalFlow(d1,
					source, stmt);
			if (ruleOut != null && !ruleOut.isEmpty()) {
				if (res == null)
					res = new HashSet<Abstraction>(ruleOut);
				else
					res.addAll(ruleOut);
			}
		}
		return res;
	}
	
	/**
	 * Applies all rules to the call-to-return flow function
	 * @param d1 The context abstraction
	 * @param source The incoming taint to propagate over the given statement
	 * @param stmt The statement to which to apply the rules
	 * @return The collection of outgoing taints
	 */
	public Set<Abstraction> applyCallToReturnFlowFunction(Abstraction d1,
			Abstraction source, Stmt stmt) {
		Set<Abstraction> res = null;
		
		for (ITaintPropagationRule rule : rules) {
			Collection<Abstraction> ruleOut = rule.propagateCallToReturnFlow(
					d1, source, stmt);
			if (ruleOut != null && !ruleOut.isEmpty()) {
				if (res == null)
					res = new HashSet<Abstraction>(ruleOut);
				else
					res.addAll(ruleOut);
			}
		}
		return res;
	}
	
}
