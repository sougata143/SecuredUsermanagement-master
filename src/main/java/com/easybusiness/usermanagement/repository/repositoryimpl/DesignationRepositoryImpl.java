package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.repository.CustomRepository.DesignationCustomRepository;

@Transactional
@Repository
public class DesignationRepositoryImpl implements DesignationCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Designation getDesignationById(Long id) {
	return entityManager.find(Designation.class, id);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Designation> getAllDesignations() {
	String hql = "FROM Designation as designation ORDER BY designation.id";
	return (List<Designation>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addDesignation(Designation designation) {
	entityManager.persist(designation);
    }

    @Override
    public void updateDesignation(Designation designation) {
	Designation designationItem = getDesignationById(designation.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteDesignation(Long id) {
	entityManager.remove(getDesignationById(id));
    }

}
