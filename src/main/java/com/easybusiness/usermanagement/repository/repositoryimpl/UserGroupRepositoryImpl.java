package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserGroup;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupCustomRepository;

@Transactional
@Repository
public class UserGroupRepositoryImpl implements UserGroupCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserGroup getUserGroupById(Long userGroupId) {
	return entityManager.find(UserGroup.class, userGroupId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserGroup> getAllUserGroups() {
	String hql = "FROM UserGroup as userGroup ORDER BY userGroup.id";
	return (List<UserGroup>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserGroup(UserGroup userGroup) {
	entityManager.persist(userGroup);
    }

    /*@Override
    public void updateUserGroup(UserGroup userGroup) {
	UserGroup userGroupItem = getUserGroupById(userGroup.getId());
	
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 
	entityManager.flush();
    }*/
    
    @Override
    public void updateUserGroup(UserGroup userGroup) {
	UserGroup userGroupItem = getUserGroupById(userGroup.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	userGroupItem.setId(userGroup.getId());
	userGroupItem.setFromDate(userGroup.getFromDate());
	userGroupItem.setIsEnable(userGroup.getIsEnable());
	userGroupItem.setModifiedBy(userGroup.getModifiedBy());
	userGroupItem.setModifiedOn(userGroup.getModifiedOn());
	userGroupItem.setToDate(userGroup.getToDate());
	userGroupItem.setUserGroupName(userGroup.getUserGroupName());
	entityManager.merge(userGroupItem);
	entityManager.flush();
    }

    @Override
    public void deleteUserGroup(Long userGroupId) {
	entityManager.remove(getUserGroupById(userGroupId));
    }
    
    @Override
	public boolean isUserGroupExist(long id, String userGroupName) {
		String hql = "FROM UserGroup as userGroup WHERE userGroup.id = ? AND userGroup.userGroupName = ?";
		int count = entityManager.createQuery(hql).setParameter(1, id).setParameter(2, userGroupName).getResultList().size();
		return count >0 ? true : false;
	}

}
