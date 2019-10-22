package com.easybusiness.usermanagement.repository;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.State;

public interface StateRepository extends CrudRepository<State, Long> {

	State findById(long id);
	
}
