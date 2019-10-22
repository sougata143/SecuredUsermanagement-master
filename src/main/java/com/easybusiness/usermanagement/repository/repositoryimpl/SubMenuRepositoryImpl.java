package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.SubMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.SubMenuCustomRepository;

@Transactional
@Repository
public class SubMenuRepositoryImpl implements SubMenuCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public SubMenu getSubMenuById(Long subMenuId) {
	return entityManager.find(SubMenu.class, subMenuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<SubMenu> getAllSubMenus() {
	String hql = "FROM SubMenu as subMenu ORDER BY subMenu.id";
	return (List<SubMenu>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addSubMenu(SubMenu subMenu) {
	entityManager.persist(subMenu);
    }

    @Override
    public void updateSubMenu(SubMenu subMenu) {
	SubMenu subMenuItem = getSubMenuById(subMenu.getId());
	/*
	 * SubMenu.setTitle(SubMenu.getTitle());
	 * SubMenu.setCategory(SubMenu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteSubMenu(Long subMenuId) {
	entityManager.remove(getSubMenuById(subMenuId));
    }

}
