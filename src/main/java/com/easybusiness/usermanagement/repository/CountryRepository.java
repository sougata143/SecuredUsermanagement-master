package com.easybusiness.usermanagement.repository;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Country;

public interface CountryRepository extends CrudRepository<Country, Long> {

	Country findById(long id);
	
}
