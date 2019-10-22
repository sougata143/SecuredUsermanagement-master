package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.repository.CustomRepository.OrganizationCustomRepository;

@Transactional
@Repository
public class OrganizationRepositoryImpl implements OrganizationCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Organization getOrganizationById(Long id) {
	return entityManager.find(Organization.class, id);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Organization> getAllOrganizations() {
	String hql = "FROM Organization as organization ORDER BY organization.id";
	return (List<Organization>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addOrganization(Organization organization) {
	entityManager.persist(organization);
    }

    @Override
    public void updateOrganization(Organization organization) {
	Organization organizationItem = getOrganizationById(organization.getId());
    }

    @Override
    public void deleteOrganization(Long id) {
	entityManager.remove(getOrganizationById(id));
    }

    @Override
    public boolean organizationExists(Long id, String orgName) {
	String hql = "FROM Organization as organization WHERE organization.id = ? and Organization.orgName = ?";
	int count = entityManager.createQuery(hql).setParameter(1, id).setParameter(2, orgName).getResultList().size();
	return count > 0 ? true : false;
    }

}
