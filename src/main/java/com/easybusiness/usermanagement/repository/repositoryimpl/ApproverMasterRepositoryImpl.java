package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.repository.CustomRepository.ApproverMasterCustomRepository;

@Transactional
@Repository
public class ApproverMasterRepositoryImpl implements ApproverMasterCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public ApproverMaster getApproverMasterById(Long approverMasterId) {
	return entityManager.find(ApproverMaster.class, approverMasterId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<ApproverMaster> getAllApproverMasters() {
	String hql = "FROM ApproverMaster as approverMaster ORDER BY approverMaster.id";
	return (List<ApproverMaster>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addApproverMaster(ApproverMaster approverMaster) {
	entityManager.merge(approverMaster);
    }

    @Override
    public void updateApproverMaster(ApproverMaster approverMaster) {
	ApproverMaster approverMasterItem = getApproverMasterById(approverMaster.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteApproverMaster(Long approverMasterId) {
	entityManager.remove(getApproverMasterById(approverMasterId));
    }

}
