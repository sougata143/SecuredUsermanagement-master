package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.Department;

public interface DepartmentCustomRepository {

    Department getDepartmentById(Long id);

    boolean departmentExists(Long id, String departmentName);

    void deleteDepartment(Long id);

    void updateDepartment(Department department);

    void addDepartment(Department department);

    List<Department> getAllDepartments();

}
