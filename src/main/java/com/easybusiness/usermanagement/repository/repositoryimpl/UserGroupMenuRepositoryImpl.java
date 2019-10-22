package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserGroupMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupMenuCustomRepository;

@Transactional
@Repository
public class UserGroupMenuRepositoryImpl implements UserGroupMenuCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserGroupMenu getUserGroupMenuById(Long userGroupMenuId) {
	return entityManager.find(UserGroupMenu.class, userGroupMenuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserGroupMenu> getAllUserGroupMenus() {
	String hql = "FROM UserGroupMenu as userGroupMenu ORDER BY userGroupMenu.id";
	return (List<UserGroupMenu>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserGroupMenu(UserGroupMenu userGroupMenu) {
	entityManager.merge(userGroupMenu);
    }

    @Override
    public void updateUserGroupMenu(UserGroupMenu userGroupMenu) {
	UserGroupMenu UserGroupMenuItem = getUserGroupMenuById(userGroupMenu.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteUserGroupMenu(Long userGroupMenuId) {
	String hql = "DELETE FROM UserGroupMenu as userGroupMenu WHERE userGroupMenu.id = ? ";
	entityManager.createQuery(hql).setParameter(1, userGroupMenuId).executeUpdate();
	//entityManager.remove(getUserGroupMenuById(userGroupMenuId));
    }

}
