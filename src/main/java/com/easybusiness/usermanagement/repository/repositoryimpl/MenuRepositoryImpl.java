package com.easybusiness.usermanagement.repository.repositoryimpl;


import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.repository.CustomRepository.MenuCustomRepository;

@Transactional
@Repository
public class MenuRepositoryImpl implements MenuCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Menu getMenuById(Long menuId) {
	return entityManager.find(Menu.class, menuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Menu> getAllMenus() {
	String hql = "FROM Menu as menu ORDER BY menu.id";
	return (List<Menu>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addMenu(Menu Menu) {
	entityManager.persist(Menu);
    }

    /*@Override
    public void updateMenu(Menu Menu) {
	Menu menu = getMenuById(Menu.getId());
	
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 
	entityManager.flush();
    }*/
    
    @Override
    public void updateMenu(Menu Menu) {
	Menu menu = getMenuById(Menu.getId());
	
	  menu.setId(Menu.getId());
	  menu.setMenuIconName(Menu.getMenuIconName());
	  menu.setMenuName(Menu.getMenuName());
	  menu.setModifiedBy(Menu.getModifiedBy());
	  menu.setModifiedTime(Menu.getModifiedTime());
	  
	  entityManager.merge(menu);
	 
	entityManager.flush();
    }

    @Override
    public void deleteMenu(Long MenuId) {
	entityManager.remove(getMenuById(MenuId));
    }

    @Override
    public boolean MenuExists(String title, String category) {
	String hql = "FROM Menu as menu WHERE menu.id = ? and menu.category = ?";
	int count = entityManager.createQuery(hql).setParameter(1, title).setParameter(2, category).getResultList()
		.size();
	return count > 0 ? true : false;
    }

}
