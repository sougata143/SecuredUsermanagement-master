package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.SubMenuUrl;
import com.easybusiness.usermanagement.repository.CustomRepository.SubMenuUrlCustomRepository;

@Transactional
@Repository
public class SubMenuUrlRepositoryImpl implements SubMenuUrlCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public SubMenuUrl getSubMenuUrlById(Long subMenuId) {
	return entityManager.find(SubMenuUrl.class, subMenuId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<SubMenuUrl> getAllSubMenuUrls() {
	String hql = "FROM SubMenuUrl as subMenuUrl ORDER BY subMenuUrl.id";
	return (List<SubMenuUrl>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addSubMenuUrl(SubMenuUrl subMenu) {
	entityManager.persist(subMenu);
    }

    @Override
    public void updateSubMenuUrl(SubMenuUrl subMenu) {
	SubMenuUrl subMenuItem = getSubMenuUrlById(subMenu.getId());
	/*
	 * SubMenuUrl.setTitle(SubMenuUrl.getTitle());
	 * SubMenuUrl.setCategory(SubMenuUrl.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteSubMenuUrl(Long subMenuId) {
	entityManager.remove(getSubMenuUrlById(subMenuId));
    }

}
