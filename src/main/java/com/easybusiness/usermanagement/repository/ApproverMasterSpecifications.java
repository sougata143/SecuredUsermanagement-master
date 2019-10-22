package com.easybusiness.usermanagement.repository;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.springframework.data.jpa.domain.Specification;

import com.easybusiness.usermanagement.entity.metadata.ApproverMaster_;
import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.entity.User;

public final class ApproverMasterSpecifications {
    
	ApproverMaster approver = new ApproverMaster();
	
    private ApproverMasterSpecifications()
    {
	
    }
    
    public static Specification<ApproverMaster> findIfUserIsAnyApprover(User user)
    {
	return new Specification<ApproverMaster>() {

	    @Override
	    public Predicate toPredicate(Root<ApproverMaster> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
		final Collection<Predicate> predicates = new ArrayList<>();
		
		final Predicate user1Predicate=cb.equal(root.get(ApproverMaster_.user1), user);
		predicates.add(user1Predicate);
		final Predicate user2Predicate=cb.equal(root.get(ApproverMaster_.user2), user);
		predicates.add(user2Predicate);
		final Predicate user3Predicate=cb.equal(root.get(ApproverMaster_.user3), user);
		predicates.add(user3Predicate);
		final Predicate user4Predicate=cb.equal(root.get(ApproverMaster_.user4), user);
		predicates.add(user4Predicate);
		final Predicate user5Predicate=cb.equal(root.get(ApproverMaster_.user5), user);
		predicates.add(user5Predicate);
		
		return cb.or(predicates.toArray(new Predicate[predicates.size()]));
	    }
	};
	
    }
    
    public static Specification<ApproverMaster> findIfUserIsAnyApproverOfParticularTask(User user,String taskId)
    {
	return new Specification<ApproverMaster>() {

	    @Override
	    public Predicate toPredicate(Root<ApproverMaster> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
		final Collection<Predicate> predicates = new ArrayList<>();
		final Predicate user1Predicate=cb.equal(root.get(ApproverMaster_.user1), user);;
		predicates.add(user1Predicate);
		final Predicate user2Predicate=cb.equal(root.get(ApproverMaster_.user2), user);;
		predicates.add(user2Predicate);
		final Predicate user3Predicate=cb.equal(root.get(ApproverMaster_.user3), user);;
		predicates.add(user3Predicate);
		final Predicate user4Predicate=cb.equal(root.get(ApproverMaster_.user4), user);;
		predicates.add(user4Predicate);
		final Predicate user5Predicate=cb.equal(root.get(ApproverMaster_.user5), user);;
		predicates.add(user5Predicate);
		return cb.and(cb.or(predicates.toArray(new Predicate[predicates.size()])),cb.equal(root.get(ApproverMaster_.id), Long.parseLong(taskId)));
	    }
	};
	
    }

}
