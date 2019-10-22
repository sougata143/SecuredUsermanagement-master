package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Branch;
import com.easybusiness.usermanagement.repository.CustomRepository.BranchCustomRepository;

@Transactional
@Repository
public class BranchRepositoryImpl implements BranchCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Branch getBranchById(Long branchId) {
	return entityManager.find(Branch.class, branchId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Branch> getAllBranches() {
	String hql = "FROM Branch as branch ORDER BY branch.id";
	return (List<Branch>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addBranch(Branch branch) {
	entityManager.persist(branch);
    }

    @Override
    public void updateBranch(Branch branch) {
	Branch BranchItem = getBranchById(branch.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteBranch(Long branchId) {
	entityManager.remove(getBranchById(branchId));
    }

}
