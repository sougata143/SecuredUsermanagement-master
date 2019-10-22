package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserGroupMap;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupMapCustomRepository;

@Transactional
@Repository
public class UserGroupMapRepositoryImpl implements UserGroupMapCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserGroupMap getUserGroupMapById(Long userGroupMapId) {
	return entityManager.find(UserGroupMap.class, userGroupMapId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserGroupMap> getAllUserGroupMaps() {
	String hql = "FROM UserGroupMap as userGroupMap ORDER BY userGroupMap.id";
	return (List<UserGroupMap>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserGroupMap(UserGroupMap UserGroupMap) {
	entityManager.merge(UserGroupMap);
    }

    @Override
    public void updateUserGroupMap(UserGroupMap UserGroupMap) {
	UserGroupMap UserGroupMapItem = getUserGroupMapById(UserGroupMap.getId());
    }

    @Override
    public void deleteUserGroupMap(Long UserGroupMapId) {
	entityManager.remove(getUserGroupMapById(UserGroupMapId));
    }

}
