package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.LocationMaster;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(LocationMaster.class)
public abstract class LocationMaster_ {

	public static volatile SingularAttribute<LocationMaster, Date> modifiedOn;
	public static volatile SingularAttribute<LocationMaster, String> locationCountry;
	public static volatile SingularAttribute<LocationMaster, String> createdBy;
	public static volatile SingularAttribute<LocationMaster, String> modifiedBy;
	public static volatile SingularAttribute<LocationMaster, Long> id;
	public static volatile SingularAttribute<LocationMaster, Long> locationPin;
	public static volatile SingularAttribute<LocationMaster, String> locationArea;
	public static volatile SingularAttribute<LocationMaster, String> locationState;
	public static volatile SingularAttribute<LocationMaster, Date> createdOn;
	public static volatile SingularAttribute<LocationMaster, String> locationCity;

}

