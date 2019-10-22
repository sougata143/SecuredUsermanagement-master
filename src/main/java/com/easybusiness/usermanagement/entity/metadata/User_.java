package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Blob;
import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Department;
import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.entity.LocationMaster;
import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.entity.User;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(User.class)
public abstract class User_ {

	public static volatile SingularAttribute<User, String> lastName;
	public static volatile SingularAttribute<User, String> permAddr;
	public static volatile SingularAttribute<User, String> country;
	public static volatile SingularAttribute<User, String> fatherName;
	public static volatile SingularAttribute<User, Blob> userImg;
	public static volatile SingularAttribute<User, String> gender;
	public static volatile SingularAttribute<User, Date> endDate;
	public static volatile SingularAttribute<User, String> city;
	public static volatile SingularAttribute<User, String> password;
	public static volatile SingularAttribute<User, Date> modifiedOn;
	public static volatile SingularAttribute<User, String> passport;
	public static volatile SingularAttribute<User, Long> unitId;
	public static volatile SingularAttribute<User, String> modifiedBy;
	public static volatile SingularAttribute<User, Long> id;
	public static volatile SingularAttribute<User, String> state;
	public static volatile SingularAttribute<User, Department> department;
	public static volatile SingularAttribute<User, String> email;
	public static volatile SingularAttribute<User, String> zip;
	public static volatile SingularAttribute<User, String> alternateEmail;
	public static volatile SingularAttribute<User, Long> mobile;
	public static volatile SingularAttribute<User, Date> dateOfBirth;
	public static volatile SingularAttribute<User, String> userName;
	public static volatile SingularAttribute<User, String> typeOfEmployment;
	public static volatile SingularAttribute<User, Date> fromDate;
	public static volatile SingularAttribute<User, String> firstName;
	public static volatile SingularAttribute<User, Organization> organization;
	public static volatile SingularAttribute<User, Long> isEnabled;
	public static volatile SingularAttribute<User, LocationMaster> location;
	public static volatile SingularAttribute<User, Designation> designation;
	public static volatile SingularAttribute<User, String> spouseName;

}

