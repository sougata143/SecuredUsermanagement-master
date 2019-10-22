package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.Designation;

public interface DesignationCustomRepository {

    Designation getDesignationById(Long id);

    void deleteDesignation(Long id);

    void updateDesignation(Designation designation);

    void addDesignation(Designation designation);

    List<Designation> getAllDesignations();

}
