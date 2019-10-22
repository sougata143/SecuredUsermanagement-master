package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.repository.CustomRepository.RoleCustomRepository;

@Transactional
@Repository
public class RoleRepositoryImpl implements RoleCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Role getRoleById(Long roleId) {
	return entityManager.find(Role.class, roleId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Role> getAllRoles() {
	String hql = "FROM Role as role ORDER BY role.id";
	return (List<Role>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addRole(Role role) {
	entityManager.persist(role);
    }

    @Override
    public void updateRole(Role role) {
	Role roleItem = getRoleById(role.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteRole(Long roleId) {
	entityManager.remove(getRoleById(roleId));
    }

    @Override
    public boolean roleExists(String roleDesc, String roleName) {
	String hql = "FROM Role as role WHERE role.roleDesc = ? and role.roleName = ?";
	int count = entityManager.createQuery(hql).setParameter(1, roleDesc).setParameter(2, roleName).getResultList()
		.size();
	return count > 0 ? true : false;
    }

}
