package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.Branch;

public interface BranchCustomRepository {

    Branch getBranchById(Long branchId);

    void deleteBranch(Long branchId);

    void updateBranch(Branch branch);

    void addBranch(Branch branch);

    List<Branch> getAllBranches();

}
