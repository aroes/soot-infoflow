/*******************************************************************************
 * Copyright (c) 2012 Eric Bodden.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * 
 * Contributors:
 *     Eric Bodden - initial API and implementation
 ******************************************************************************/
package soot.jimple.infoflow.solver.fastSolver;

import heros.SynchronizedBy;
import heros.ThreadSafe;
import heros.solver.PathEdge;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.collect.Maps;


/**
 * The IDE algorithm uses a list of jump functions. Instead of a list, we use a set of three
 * maps that are kept in sync. This allows for efficient indexing: the algorithm accesses
 * elements from the list through three different indices.
 */
@ThreadSafe
public class JumpFunctions<N,D> {
	
	private class ReverseEntry {
		private final N n;
		private final D d;
		private final int hashCode;
		
		public ReverseEntry(N n, D d) {
			this.n = n;
			this.d = d;

			final int prime = 31;
			int result = 1;
			result = prime * result + ((d == null) ? 0 : d.hashCode());
			result = prime * result + ((n == null) ? 0 : n.hashCode());
			this.hashCode = result;
		}
		
		@Override
		public int hashCode() {
			return this.hashCode;
		}

		@SuppressWarnings("unchecked")
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null || !(obj instanceof JumpFunctions.ReverseEntry))
				return false;
			ReverseEntry other = (ReverseEntry) obj;
			if (d == null) {
				if (other.d != null)
					return false;
			} else if (!d.equals(other.d))
				return false;
			if (n == null) {
				if (other.n != null)
					return false;
			} else if (!n.equals(other.n))
				return false;
			return true;
		}
	}
	
	//mapping from target node and value to a list of all source values and associated functions
	//where the list is implemented as a mapping from the source value to the function
	//we exclude empty default functions
	@SynchronizedBy("consistent lock on this")
	protected Map<ReverseEntry,Map<D,D>> nonEmptyReverseLookup = Maps.newHashMap();
	
	public JumpFunctions() {
	}

	/**
	 * Records a jump function. The source statement is implicit.
	 * @see PathEdge
	 */
	public D addFunction(D sourceVal, N target, D targetVal) {
		assert sourceVal!=null;
		assert target!=null;
		assert targetVal!=null;
		
		Map<D, D> sourceValToFunc = null;
		synchronized (this) {
			ReverseEntry entry = new ReverseEntry(target, targetVal);
			sourceValToFunc = nonEmptyReverseLookup.get(entry);
			if(sourceValToFunc==null) {
				sourceValToFunc = new ConcurrentHashMap<D, D>();
				nonEmptyReverseLookup.put(entry, sourceValToFunc);
			}
			
			D existingVal = sourceValToFunc.get(sourceVal);
			if (existingVal != null)
				return existingVal;
			sourceValToFunc.put(sourceVal, targetVal);
			return null;
		}
	}
	
	/**
     * Returns, for a given target statement and value all associated
     * source values, and for each the associated edge function.
     * The return value is a mapping from source value to function.
	 */
	public Set<D> reverseLookup(N target, D targetVal) {
		assert target!=null;
		assert targetVal!=null;
		Map<D, D> res = nonEmptyReverseLookup.get(new ReverseEntry(target,targetVal));
		if (res ==null)
			return Collections.emptySet();
		return res.keySet();
	}
	
	/**
	 * Removes a jump function. The source statement is implicit.
	 * @see PathEdge
	 * @return True if the function has actually been removed. False if it was not
	 * there anyway.
	 */
	public synchronized boolean removeFunction(D sourceVal, N target, D targetVal) {
		assert sourceVal!=null;
		assert target!=null;
		assert targetVal!=null;
		
		ReverseEntry entry = new ReverseEntry(target, targetVal);
		Map<D, D> sourceValToFunc = nonEmptyReverseLookup.get(entry);
		if (sourceValToFunc == null)
			return false;
		if (sourceValToFunc.remove(sourceVal) == null)
			return false;
		if (sourceValToFunc.isEmpty())
			nonEmptyReverseLookup.remove(entry);
		
		return true;
	}
	
	/**
	 * Removes all jump functions
	 */
	public synchronized void clear() {
		this.nonEmptyReverseLookup.clear();
	}

}
