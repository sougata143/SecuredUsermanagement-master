package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserGroupMenuSubMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupMenuSubMenuCustomRepository;

@Transactional
@Repository
public class UserGroupMenuSubMenuRepositoryImpl implements UserGroupMenuSubMenuCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserGroupMenuSubMenu getUserGroupMenuById(Long userGroupMenuId) {
	return entityManager.find(UserGroupMenuSubMenu.class, userGroupMenuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserGroupMenuSubMenu> getAllUserGroupMenus() {
	String hql = "FROM UserGroupMenuSubMenu as userGroupMenu ORDER BY userGroupMenu.id";
	return (List<UserGroupMenuSubMenu>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserGroupMenu(UserGroupMenuSubMenu userGroupMenu) {
	entityManager.merge(userGroupMenu);
    }

    @Override
    public void updateUserGroupMenu(UserGroupMenuSubMenu userGroupMenu) {
	UserGroupMenuSubMenu UserGroupMenuItem = getUserGroupMenuById(userGroupMenu.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	UserGroupMenuItem.setFromDate(UserGroupMenuItem.getFromDate());
	UserGroupMenuItem.setIsEnable(UserGroupMenuItem.getIsEnable());
	UserGroupMenuItem.setMenuItem(UserGroupMenuItem.getMenuItem());
	UserGroupMenuItem.setModifiedBy(UserGroupMenuItem.getModifiedBy());
	UserGroupMenuItem.setModifiedOn(UserGroupMenuItem.getModifiedOn());
	UserGroupMenuItem.setSubMenuItem(UserGroupMenuItem.getSubMenuItem());
	UserGroupMenuItem.setToDate(UserGroupMenuItem.getToDate());
	UserGroupMenuItem.setUserGroup(UserGroupMenuItem.getUserGroup());
	UserGroupMenuItem.setReadonly(UserGroupMenuItem.getReadonly());
	entityManager.merge(UserGroupMenuItem);
	entityManager.flush();
    }

    @Override
    public void deleteUserGroupMenu(Long userGroupMenuId) {
	String hql = "DELETE FROM UserGroupMenuSubMenu as userGroupMenuSubMenu WHERE userGroupMenuSubMenu.id = ? ";
	entityManager.createQuery(hql).setParameter(1, userGroupMenuId).executeUpdate();
	/*
	entityManager.remove(getUserGroupMenuById(userGroupMenuId));*/
    }

}
