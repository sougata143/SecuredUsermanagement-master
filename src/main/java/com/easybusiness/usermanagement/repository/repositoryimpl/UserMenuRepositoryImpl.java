package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.UserMenuCustomRepository;

@Transactional
@Repository
public class UserMenuRepositoryImpl implements UserMenuCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserMenu getUserMenuById(Long userMenuId) {
	return entityManager.find(UserMenu.class, userMenuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserMenu> getAllUserMenus() {
	String hql = "FROM UserMenu as userMenu ORDER BY userMenu.id";
	return (List<UserMenu>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserMenu(UserMenu userMenu) {
	entityManager.persist(userMenu);
    }

    @Override
    public void updateUserMenu(UserMenu userMenu) {
	UserMenu userMenuItem = getUserMenuById(userMenu.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteUserMenu(Long userMenuId) {
	entityManager.remove(getUserMenuById(userMenuId));
    }

}
