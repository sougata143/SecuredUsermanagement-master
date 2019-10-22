package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.RoleActionMap;
import com.easybusiness.usermanagement.repository.CustomRepository.RoleActionMapCustomRepository;

@Transactional
@Repository
public class RoleActionMapRepositoryImpl implements RoleActionMapCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public RoleActionMap getRoleActionMapById(Long roleActionMapId) {
	return entityManager.find(RoleActionMap.class, roleActionMapId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<RoleActionMap> getAllRoleActionMaps() {
	String hql = "FROM RoleActionMap as roleActionMap ORDER BY roleActionMap.id";
	return (List<RoleActionMap>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addRoleActionMap(RoleActionMap roleActionMap) {
	entityManager.persist(roleActionMap);
    }

    @Override
    public void updateRoleActionMap(RoleActionMap roleActionMap) {
	RoleActionMap RoleActionMapItem = getRoleActionMapById(roleActionMap.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteRoleActionMap(Long roleActionMapId) {
	entityManager.remove(getRoleActionMapById(roleActionMapId));
    }

}
