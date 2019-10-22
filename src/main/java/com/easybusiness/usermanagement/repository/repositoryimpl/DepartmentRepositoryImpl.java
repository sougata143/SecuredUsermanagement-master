package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Department;
import com.easybusiness.usermanagement.repository.CustomRepository.DepartmentCustomRepository;

@Transactional
@Repository
public class DepartmentRepositoryImpl implements DepartmentCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Department getDepartmentById(Long id) {
	return entityManager.find(Department.class, id);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Department> getAllDepartments() {
	String hql = "FROM Department as department ORDER BY department.id";
	return (List<Department>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addDepartment(Department department) {
	entityManager.merge(department);
    }

    @Override
    public void updateDepartment(Department department) {
	Department departmentItem = getDepartmentById(department.getId());
	
    }

    @Override
    public void deleteDepartment(Long id) {
	entityManager.remove(getDepartmentById(id));
    }

    @Override
    public boolean departmentExists(Long id, String deptName) {
	String hql = "FROM Department as department WHERE department.id = ? and department.deptName = ?";
	int count = entityManager.createQuery(hql).setParameter(1, id).setParameter(2, deptName).getResultList().size();
	return count > 0 ? true : false;
    }

}
