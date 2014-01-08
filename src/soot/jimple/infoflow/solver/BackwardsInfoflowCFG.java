package soot.jimple.infoflow.solver;

import soot.jimple.toolkits.ide.icfg.BackwardsInterproceduralCFG;


public class BackwardsInfoflowCFG extends InfoflowCFG {

	public BackwardsInfoflowCFG() {
		super(new BackwardsInterproceduralCFG());
	}
	
}
