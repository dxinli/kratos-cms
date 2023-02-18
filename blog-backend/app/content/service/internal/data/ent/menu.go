// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"kratos-blog/app/content/service/internal/data/ent/menu"
	"strings"

	"entgo.io/ent/dialect/sql"
)

// Menu is the model entity for the Menu schema.
type Menu struct {
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
	// 目录名
	Name *string `json:"name,omitempty"`
	// 链接
	URL *string `json:"url,omitempty"`
	// 优先级
	Priority *int32 `json:"priority,omitempty"`
	// 目标
	Target *string `json:"target,omitempty"`
	// 图标
	Icon *string `json:"icon,omitempty"`
	// 父目录ID
	ParentID *uint32 `json:"parent_id,omitempty"`
	// 分组
	Team *string `json:"team,omitempty"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Menu) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case menu.FieldID, menu.FieldCreateTime, menu.FieldUpdateTime, menu.FieldDeleteTime, menu.FieldPriority, menu.FieldParentID:
			values[i] = new(sql.NullInt64)
		case menu.FieldName, menu.FieldURL, menu.FieldTarget, menu.FieldIcon, menu.FieldTeam:
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Menu", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Menu fields.
func (m *Menu) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case menu.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			m.ID = uint32(value.Int64)
		case menu.FieldCreateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				m.CreateTime = new(int64)
				*m.CreateTime = value.Int64
			}
		case menu.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				m.UpdateTime = new(int64)
				*m.UpdateTime = value.Int64
			}
		case menu.FieldDeleteTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field delete_time", values[i])
			} else if value.Valid {
				m.DeleteTime = new(int64)
				*m.DeleteTime = value.Int64
			}
		case menu.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				m.Name = new(string)
				*m.Name = value.String
			}
		case menu.FieldURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field url", values[i])
			} else if value.Valid {
				m.URL = new(string)
				*m.URL = value.String
			}
		case menu.FieldPriority:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field priority", values[i])
			} else if value.Valid {
				m.Priority = new(int32)
				*m.Priority = int32(value.Int64)
			}
		case menu.FieldTarget:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field target", values[i])
			} else if value.Valid {
				m.Target = new(string)
				*m.Target = value.String
			}
		case menu.FieldIcon:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field icon", values[i])
			} else if value.Valid {
				m.Icon = new(string)
				*m.Icon = value.String
			}
		case menu.FieldParentID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field parent_id", values[i])
			} else if value.Valid {
				m.ParentID = new(uint32)
				*m.ParentID = uint32(value.Int64)
			}
		case menu.FieldTeam:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field team", values[i])
			} else if value.Valid {
				m.Team = new(string)
				*m.Team = value.String
			}
		}
	}
	return nil
}

// Update returns a builder for updating this Menu.
// Note that you need to call Menu.Unwrap() before calling this method if this Menu
// was returned from a transaction, and the transaction was committed or rolled back.
func (m *Menu) Update() *MenuUpdateOne {
	return NewMenuClient(m.config).UpdateOne(m)
}

// Unwrap unwraps the Menu entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (m *Menu) Unwrap() *Menu {
	_tx, ok := m.config.driver.(*txDriver)
	if !ok {
		panic("ent: Menu is not a transactional entity")
	}
	m.config.driver = _tx.drv
	return m
}

// String implements the fmt.Stringer.
func (m *Menu) String() string {
	var builder strings.Builder
	builder.WriteString("Menu(")
	builder.WriteString(fmt.Sprintf("id=%v, ", m.ID))
	if v := m.CreateTime; v != nil {
		builder.WriteString("create_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := m.UpdateTime; v != nil {
		builder.WriteString("update_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := m.DeleteTime; v != nil {
		builder.WriteString("delete_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := m.Name; v != nil {
		builder.WriteString("name=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := m.URL; v != nil {
		builder.WriteString("url=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := m.Priority; v != nil {
		builder.WriteString("priority=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := m.Target; v != nil {
		builder.WriteString("target=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := m.Icon; v != nil {
		builder.WriteString("icon=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := m.ParentID; v != nil {
		builder.WriteString("parent_id=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := m.Team; v != nil {
		builder.WriteString("team=")
		builder.WriteString(*v)
	}
	builder.WriteByte(')')
	return builder.String()
}

// Menus is a parsable slice of Menu.
type Menus []*Menu

func (m Menus) config(cfg config) {
	for _i := range m {
		m[_i].config = cfg
	}
}
