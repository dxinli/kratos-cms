// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"kratos-blog/app/content/service/internal/data/ent/link"
	"strings"

	"entgo.io/ent/dialect/sql"
)

// Link is the model entity for the Link schema.
type Link struct {
	config `json:"-"`
	// ID of the ent.
	// id
	ID uint32 `json:"id,omitempty"`
	// 创建时间
	CreateTime *int64 `json:"create_time,omitempty"`
	// 更新时间
	UpdateTime *int64 `json:"update_time,omitempty"`
	// 删除时间
	DeleteTime *int64 `json:"delete_time,omitempty"`
	// 链接名
	Name *string `json:"name,omitempty"`
	// 链接
	URL *string `json:"url,omitempty"`
	// 图标
	Logo *string `json:"logo,omitempty"`
	// 说明
	Description *string `json:"description,omitempty"`
	// 分组
	Team *string `json:"team,omitempty"`
	// 优先级
	Priority *int32 `json:"priority,omitempty"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Link) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case link.FieldID, link.FieldCreateTime, link.FieldUpdateTime, link.FieldDeleteTime, link.FieldPriority:
			values[i] = new(sql.NullInt64)
		case link.FieldName, link.FieldURL, link.FieldLogo, link.FieldDescription, link.FieldTeam:
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Link", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Link fields.
func (l *Link) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case link.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			l.ID = uint32(value.Int64)
		case link.FieldCreateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				l.CreateTime = new(int64)
				*l.CreateTime = value.Int64
			}
		case link.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				l.UpdateTime = new(int64)
				*l.UpdateTime = value.Int64
			}
		case link.FieldDeleteTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field delete_time", values[i])
			} else if value.Valid {
				l.DeleteTime = new(int64)
				*l.DeleteTime = value.Int64
			}
		case link.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				l.Name = new(string)
				*l.Name = value.String
			}
		case link.FieldURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field url", values[i])
			} else if value.Valid {
				l.URL = new(string)
				*l.URL = value.String
			}
		case link.FieldLogo:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field logo", values[i])
			} else if value.Valid {
				l.Logo = new(string)
				*l.Logo = value.String
			}
		case link.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				l.Description = new(string)
				*l.Description = value.String
			}
		case link.FieldTeam:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field team", values[i])
			} else if value.Valid {
				l.Team = new(string)
				*l.Team = value.String
			}
		case link.FieldPriority:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field priority", values[i])
			} else if value.Valid {
				l.Priority = new(int32)
				*l.Priority = int32(value.Int64)
			}
		}
	}
	return nil
}

// Update returns a builder for updating this Link.
// Note that you need to call Link.Unwrap() before calling this method if this Link
// was returned from a transaction, and the transaction was committed or rolled back.
func (l *Link) Update() *LinkUpdateOne {
	return NewLinkClient(l.config).UpdateOne(l)
}

// Unwrap unwraps the Link entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (l *Link) Unwrap() *Link {
	_tx, ok := l.config.driver.(*txDriver)
	if !ok {
		panic("ent: Link is not a transactional entity")
	}
	l.config.driver = _tx.drv
	return l
}

// String implements the fmt.Stringer.
func (l *Link) String() string {
	var builder strings.Builder
	builder.WriteString("Link(")
	builder.WriteString(fmt.Sprintf("id=%v, ", l.ID))
	if v := l.CreateTime; v != nil {
		builder.WriteString("create_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := l.UpdateTime; v != nil {
		builder.WriteString("update_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := l.DeleteTime; v != nil {
		builder.WriteString("delete_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := l.Name; v != nil {
		builder.WriteString("name=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := l.URL; v != nil {
		builder.WriteString("url=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := l.Logo; v != nil {
		builder.WriteString("logo=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := l.Description; v != nil {
		builder.WriteString("description=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := l.Team; v != nil {
		builder.WriteString("team=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := l.Priority; v != nil {
		builder.WriteString("priority=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteByte(')')
	return builder.String()
}

// Links is a parsable slice of Link.
type Links []*Link

func (l Links) config(cfg config) {
	for _i := range l {
		l[_i].config = cfg
	}
}
